"""
Alert Manager

Dispatches security alerts for privilege escalation attempts,
scope violations, and other containment breaches.
"""

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional

from sentinelagi.core.config import get_settings
from sentinelagi.core.models import AlertLevel, SecurityAlert
from sentinelagi.monitoring.audit_logger import audit_logger

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages security alert dispatch and escalation."""
    
    def __init__(self):
        self.config = get_settings().security
        self._handlers: List[Callable[[SecurityAlert], None]] = []
        self._alert_history: Dict[str, List[SecurityAlert]] = defaultdict(list)
        self._escalation_counts: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
    
    def register_handler(self, handler: Callable[[SecurityAlert], None]) -> None:
        """Register a callback for alert dispatch."""
        self._handlers.append(handler)
    
    async def dispatch_alert(self, alert: SecurityAlert) -> None:
        """
        Dispatch a security alert to all registered handlers.
        
        Also handles escalation for repeated violations from
        the same agent.
        """
        async with self._lock:
            self._alert_history[alert.agent_id].append(alert)
            
            # Check for escalation
            recent_alerts = [
                a for a in self._alert_history[alert.agent_id]
                if a.alert_type == alert.alert_type
            ]
            
            if len(recent_alerts) >= self.config.privilege_escalation_threshold:
                # Escalate alert level
                if alert.level == AlertLevel.WARNING:
                    alert.level = AlertLevel.CRITICAL
                elif alert.level == AlertLevel.CRITICAL:
                    alert.level = AlertLevel.EMERGENCY
                
                self._escalation_counts[alert.agent_id] += 1
                alert.message = f"[ESCALATED x{self._escalation_counts[alert.agent_id]}] {alert.message}"
            
            # Log to audit stream
            await audit_logger.log_alert(alert)
            
            # Call handlers
            for handler in self._handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(alert)
                    else:
                        handler(alert)
                except Exception as e:
                    logger.error(f"Alert handler failed: {e}")
            
            logger.warning(f"Alert dispatched: [{alert.level.value}] {alert.alert_type}")
    
    async def check_privilege_escalation(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        violation_count: int,
    ) -> Optional[SecurityAlert]:
        """
        Check if agent behavior indicates privilege escalation.
        
        Returns alert if escalation detected, None otherwise.
        """
        if violation_count < self.config.privilege_escalation_threshold:
            return None
        
        alert = SecurityAlert(
            level=AlertLevel.CRITICAL,
            agent_id=agent_id,
            session_id="",  # Will be filled by caller
            alert_type="privilege_escalation",
            message=(
                f"Agent attempted to use unauthorized tool '{tool_name}' "
                f"({violation_count} violations). "
                f"Parameters: {parameters}"
            ),
            context={
                "tool_name": tool_name,
                "parameters": parameters,
                "violation_count": violation_count,
                "threshold": self.config.privilege_escalation_threshold,
            },
        )
        
        await self.dispatch_alert(alert)
        return alert
    
    async def check_chain_escalation(
        self,
        agent_id: str,
        recent_tools: List[str],
    ) -> Optional[SecurityAlert]:
        """
        Detect privilege escalation through tool chaining patterns.
        
        Detects sequences like: recon -> execution -> system access
        """
        if len(recent_tools) < 3:
            return None
        
        # Pattern detection
        recon_tools = {"web_search", "api_call"}
        exec_tools = {"python_execute", "bash_execute"}
        system_tools = {"system", "network"}
        
        has_recon = any(t in recon_tools for t in recent_tools[-5:])
        has_exec = any(t in exec_tools for t in recent_tools[-5:])
        has_system = any(t in system_tools for t in recent_tools[-5:])
        
        if has_recon and has_exec and has_system:
            alert = SecurityAlert(
                level=AlertLevel.CRITICAL,
                agent_id=agent_id,
                session_id="",
                alert_type="chain_escalation",
                message=(
                    f"Potential chain escalation detected: "
                    f"reconnaissance -> execution -> system access. "
                    f"Recent tools: {recent_tools[-5:]}"
                ),
                context={"recent_tools": recent_tools[-5:]},
            )
            
            await self.dispatch_alert(alert)
            return alert
        
        return None
    
    async def handle_violation(
        self,
        agent_id: str,
        violation_type: str,
        details: Dict[str, Any],
    ) -> SecurityAlert:
        """Handle a policy violation and create appropriate alert."""
        alert = SecurityAlert(
            level=AlertLevel.WARNING,
            agent_id=agent_id,
            session_id=details.get("session_id", ""),
            alert_type=violation_type,
            message=f"Policy violation: {violation_type}",
            mitre_technique_id=details.get("mitre_technique_id"),
            context=details,
        )
        
        await self.dispatch_alert(alert)
        return alert
    
    def get_agent_alert_history(self, agent_id: str) -> List[SecurityAlert]:
        """Get alert history for a specific agent."""
        return self._alert_history.get(agent_id, [])
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of all alerts."""
        total_alerts = sum(len(alerts) for alerts in self._alert_history.values())
        
        by_level = defaultdict(int)
        by_type = defaultdict(int)
        
        for alerts in self._alert_history.values():
            for alert in alerts:
                by_level[alert.level.value] += 1
                by_type[alert.alert_type] += 1
        
        return {
            "total_alerts": total_alerts,
            "affected_agents": len(self._alert_history),
            "by_level": dict(by_level),
            "by_type": dict(by_type),
            "escalated_agents": len(self._escalation_counts),
        }


# Singleton
alert_manager = AlertManager()
