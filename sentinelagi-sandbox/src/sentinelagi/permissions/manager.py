"""
Permission Manager

Core permission system that enforces tool-level access control,
validates tool calls against declared scopes, and detects
privilege escalation attempts.
"""

import asyncio
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from sentinelagi.core.config import get_settings
from sentinelagi.core.exceptions import (
    PrivilegeEscalationError,
    ScopeViolationError,
    ToolNotAuthorizedError,
)
from sentinelagi.core.models import (
    AgentProfile,
    SecurityAlert,
    ToolCall,
    ToolCategory,
    ToolPermission,
)
from sentinelagi.permissions.mitre_atlas import mitre_mapper


class PermissionManager:
    """Manages tool permissions and detects policy violations."""
    
    def __init__(self):
        self.settings = get_settings().security
        self.agent_permissions: Dict[str, List[ToolPermission]] = {}
        self.tool_call_history: Dict[str, List[Dict]] = defaultdict(list)
        self.violation_counts: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
    
    def register_agent(self, agent: AgentProfile) -> None:
        """Register an agent's permissions."""
        self.agent_permissions[agent.agent_id] = agent.permissions
        self.tool_call_history[agent.agent_id] = []
        self.violation_counts[agent.agent_id] = 0
    
    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent and clean up."""
        self.agent_permissions.pop(agent_id, None)
        self.tool_call_history.pop(agent_id, None)
        self.violation_counts.pop(agent_id, None)
    
    def check_permission(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> tuple[bool, Optional[str], Optional[List[str]]]:
        """
        Check if agent has permission to use a tool.
        
        Returns:
            Tuple of (allowed, reason_if_denied, mitre_technique_ids)
        """
        permissions = self.agent_permissions.get(agent_id, [])
        parameters = parameters or {}
        
        # Find matching permission
        matched_perm = None
        for perm in permissions:
            if perm.tool_name == tool_name:
                matched_perm = perm
                break
        
        if matched_perm is None:
            # No explicit permission found - deny by default
            return (
                False,
                f"Tool '{tool_name}' not in agent's permission scope",
                ["AML.T0044"],
            )
        
        if not matched_perm.allowed:
            return (
                False,
                f"Tool '{tool_name}' is explicitly blocked",
                ["AML.T0044"],
            )
        
        # Check parameter-level restrictions
        if matched_perm.allowed_parameters is not None:
            for param in parameters.keys():
                if param not in matched_perm.allowed_parameters:
                    return (
                        False,
                        f"Parameter '{param}' not allowed for tool '{tool_name}'",
                        ["AML.T0044"],
                    )
        
        for blocked_param in matched_perm.blocked_parameters:
            if blocked_param in parameters:
                return (
                    False,
                    f"Blocked parameter '{blocked_param}' detected",
                    ["AML.T0044"],
                )
        
        # Check rate limit
        if matched_perm.rate_limit:
            recent_calls = [
                c for c in self.tool_call_history.get(agent_id, [])
                if c["tool_name"] == tool_name
                and time.time() - c["timestamp"] < 60
            ]
            if len(recent_calls) >= matched_perm.rate_limit:
                return (
                    False,
                    f"Rate limit exceeded for tool '{tool_name}'",
                    None,
                )
        
        # Detect MITRE ATLAS techniques
        category = self._infer_category(tool_name)
        detected_techniques = mitre_mapper.detect_techniques(
            tool_name, category, parameters
        )
        
        mitre_ids = [t.technique_id for t in detected_techniques] if detected_techniques else None
        
        return (True, None, mitre_ids)
    
    async def validate_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ToolCall:
        """
        Validate and record a tool call.
        
        Raises:
            ToolNotAuthorizedError: If tool is not authorized
            PrivilegeEscalationError: If privilege escalation is detected
            ScopeViolationError: If scope violation is detected
        """
        allowed, reason, mitre_ids = self.check_permission(
            agent_id, tool_name, parameters
        )
        
        tool_call = ToolCall(
            tool_name=tool_name,
            parameters=parameters or {},
            agent_id=agent_id,
            session_id=agent_id,  # Will be updated by caller
            authorized=allowed,
            mitre_technique_id=mitre_ids[0] if mitre_ids else None,
        )
        
        if not allowed:
            async with self._lock:
                self.violation_counts[agent_id] += 1
                self.tool_call_history[agent_id].append({
                    "tool_name": tool_name,
                    "timestamp": time.time(),
                    "authorized": False,
                    "reason": reason,
                })
            
            # Check escalation threshold
            if self.violation_counts[agent_id] >= self.settings.privilege_escalation_threshold:
                raise PrivilegeEscalationError(
                    f"Agent {agent_id} exceeded violation threshold. "
                    f"Count: {self.violation_counts[agent_id]}",
                    details={
                        "agent_id": agent_id,
                        "tool_name": tool_name,
                        "violation_count": self.violation_counts[agent_id],
                        "mitre_techniques": mitre_ids,
                    },
                )
            
            raise ToolNotAuthorizedError(
                reason or f"Tool '{tool_name}' not authorized",
                details={
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "mitre_techniques": mitre_ids,
                },
            )
        
        # Record authorized call
        async with self._lock:
            self.tool_call_history[agent_id].append({
                "tool_name": tool_name,
                "timestamp": time.time(),
                "authorized": True,
            })
        
        return tool_call
    
    def detect_chain_escalation(
        self,
        agent_id: str,
        recent_calls: List[ToolCall],
    ) -> Optional[SecurityAlert]:
        """
        Detect privilege escalation through tool chaining.
        
        Analyzes recent tool calls to detect patterns where
        multiple tools are used in sequence to achieve
        escalated privileges.
        """
        if len(recent_calls) < 3:
            return None
        
        # Pattern: reconnaissance → code execution → system access
        categories = [self._infer_category(c.tool_name) for c in recent_calls[-5:]]
        
        has_recon = ToolCategory.WEB_SEARCH in categories or ToolCategory.API_CALL in categories
        has_exec = ToolCategory.CODE_EXECUTION in categories
        has_system = ToolCategory.SYSTEM in categories or ToolCategory.NETWORK in categories
        
        if has_recon and has_exec and has_system:
            return SecurityAlert(
                level="critical",
                agent_id=agent_id,
                session_id=recent_calls[-1].session_id,
                alert_type="chain_escalation",
                message=(
                    f"Potential chain escalation detected: "
                    f"reconnaissance → execution → system access"
                ),
                mitre_technique_id="AML.T0044",
                context={
                    "recent_tools": [c.tool_name for c in recent_calls[-5:]],
                    "categories": [c.value for c in categories],
                },
            )
        
        return None
    
    def get_violation_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get violation summary for an agent."""
        return {
            "agent_id": agent_id,
            "total_violations": self.violation_counts.get(agent_id, 0),
            "total_tool_calls": len(self.tool_call_history.get(agent_id, [])),
            "violation_rate": (
                self.violation_counts.get(agent_id, 0) /
                max(len(self.tool_call_history.get(agent_id, [])), 1)
            ),
        }
    
    @staticmethod
    def _infer_category(tool_name: str) -> ToolCategory:
        """Infer tool category from tool name."""
        category_map = {
            "search": ToolCategory.WEB_SEARCH,
            "web_search": ToolCategory.WEB_SEARCH,
            "python": ToolCategory.CODE_EXECUTION,
            "execute": ToolCategory.CODE_EXECUTION,
            "bash": ToolCategory.CODE_EXECUTION,
            "read_file": ToolCategory.FILE_IO,
            "write_file": ToolCategory.FILE_IO,
            "http": ToolCategory.NETWORK,
            "api_call": ToolCategory.API_CALL,
            "sql": ToolCategory.DATABASE,
            "system": ToolCategory.SYSTEM,
            "analyze": ToolCategory.DATA_ANALYSIS,
        }
        
        for prefix, category in category_map.items():
            if prefix in tool_name.lower():
                return category
        
        return ToolCategory.SYSTEM


# Singleton
permission_manager = PermissionManager()
