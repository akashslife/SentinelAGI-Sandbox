"""
SentinelAGI Data Models

Pydantic models for agents, tools, permissions, audit events, and
MITRE ATLAS mappings.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ==================== Enums ====================

class AgentState(str, Enum):
    """Agent lifecycle states."""
    PENDING = "pending"
    PLANNING = "planning"
    EXECUTING = "executing"
    CRITIQUING = "critiquing"
    CORRECTING = "correcting"
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"


class ToolCategory(str, Enum):
    """Tool classification for permission scoping."""
    WEB_SEARCH = "web_search"
    CODE_EXECUTION = "code_execution"
    FILE_IO = "file_io"
    NETWORK = "network"
    SYSTEM = "system"
    DATABASE = "database"
    API_CALL = "api_call"
    DATA_ANALYSIS = "data_analysis"


class ActionType(str, Enum):
    """Types of actions logged in audit stream."""
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    PLAN_CREATED = "plan_created"
    PLAN_STEP = "plan_step"
    CRITIQUE_PASSED = "critique_passed"
    CRITIQUE_FAILED = "critique_failed"
    SELF_CORRECTION = "self_correction"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"
    SCOPE_VIOLATION = "scope_violation"
    AGENT_CREATED = "agent_created"
    AGENT_KILLED = "agent_killed"
    RESOURCE_LIMIT_HIT = "resource_limit_hit"


class AlertLevel(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


# ==================== Tool Models ====================

class ToolPermission(BaseModel):
    """Permission specification for a single tool."""
    tool_name: str
    category: ToolCategory
    allowed: bool = True
    rate_limit: Optional[int] = None  # calls per minute
    max_input_size: Optional[int] = None  # bytes
    allowed_parameters: Optional[List[str]] = None
    blocked_parameters: List[str] = Field(default_factory=list)
    require_critic_review: bool = False

    @field_validator("rate_limit")
    @classmethod
    def validate_rate_limit(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 1:
            raise ValueError("rate_limit must be at least 1")
        return v


class ToolCall(BaseModel):
    """A single tool invocation record."""
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    agent_id: str
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    execution_time_ms: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    authorized: bool = True
    mitre_technique_id: Optional[str] = None


# ==================== Agent Models ====================

class AgentProfile(BaseModel):
    """Agent identity and capability profile."""
    agent_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    permissions: List[ToolPermission] = Field(default_factory=list)
    resource_quota: "ResourceQuota" = Field(default_factory=lambda: ResourceQuota())
    max_planning_steps: int = 20
    enable_self_correction: bool = True
    enable_critic_review: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def has_tool_permission(self, tool_name: str) -> bool:
        """Check if agent has permission to use a tool."""
        for perm in self.permissions:
            if perm.tool_name == tool_name:
                return perm.allowed
        return False

    def get_tool_permission(self, tool_name: str) -> Optional[ToolPermission]:
        """Get permission details for a tool."""
        for perm in self.permissions:
            if perm.tool_name == tool_name:
                return perm
        return None


class ResourceQuota(BaseModel):
    """Resource limits for an agent."""
    max_cpu_cores: float = 1.0
    max_memory_mb: int = 512
    max_storage_mb: int = 1024
    max_execution_time_sec: int = 300
    max_tool_calls_per_minute: int = 60
    max_concurrent_tasks: int = 3


class AgentStatus(BaseModel):
    """Runtime agent status snapshot."""
    agent_id: str
    state: AgentState = AgentState.PENDING
    current_step: int = 0
    total_steps: int = 0
    tool_calls_count: int = 0
    corrections_count: int = 0
    violations_count: int = 0
    start_time: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0


# ==================== Plan Models ====================

class PlanStep(BaseModel):
    """A single step in an agent's execution plan."""
    step_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    description: str
    tool_calls: List[str] = Field(default_factory=list)  # tool names
    dependencies: List[str] = Field(default_factory=list)  # step_ids
    estimated_cost: Optional[float] = None
    requires_critic: bool = True
    status: str = "pending"  # pending, running, completed, failed, skipped
    result: Optional[Any] = None


class ExecutionPlan(BaseModel):
    """Multi-step plan for agent execution."""
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    session_id: str
    goal: str
    steps: List[PlanStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    current_step_index: int = 0
    is_long_horizon: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ==================== Audit Models ====================

class AuditEvent(BaseModel):
    """Single audit event for Redis stream logging."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action_type: ActionType
    agent_id: str
    session_id: str
    tool_name: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    result_summary: Optional[str] = None
    authorized: bool = True
    violation_type: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    execution_time_ms: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_redis_dict(self) -> Dict[str, str]:
        """Convert to flat dict for Redis stream."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "action_type": self.action_type.value,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name or "",
            "parameters": str(self.parameters or {}),
            "result_summary": self.result_summary or "",
            "authorized": str(self.authorized),
            "violation_type": self.violation_type or "",
            "mitre_technique_id": self.mitre_technique_id or "",
            "execution_time_ms": str(self.execution_time_ms or 0),
            "metadata": str(self.metadata),
        }


class SecurityAlert(BaseModel):
    """Security alert generated by monitoring layer."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: AlertLevel
    agent_id: str
    session_id: str
    alert_type: str
    message: str
    mitre_technique_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = False


# ==================== MITRE ATLAS Models ====================

class MITRETechnique(BaseModel):
    """MITRE ATLAS technique mapping."""
    technique_id: str  # e.g., "AML.T0000"
    name: str
    description: str
    tactics: List[str] = Field(default_factory=list)
    tool_categories: List[ToolCategory] = Field(default_factory=list)
    severity: str = "medium"
    indicators: List[str] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)


class CriticReviewResult(BaseModel):
    """Result of Constitutional AI critic review."""
    review_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    original_output: str
    passed: bool
    violations: List[str] = Field(default_factory=list)
    mitre_mappings: List[str] = Field(default_factory=list)
    suggested_correction: Optional[str] = None
    confidence_score: float = Field(ge=0.0, le=1.0, default=1.0)
    review_time_ms: Optional[float] = None


# ==================== API Models ====================

class CreateAgentRequest(BaseModel):
    """Request to create a new agent."""
    name: str
    description: Optional[str] = None
    permissions: List[ToolPermission] = Field(default_factory=list)
    resource_quota: Optional[ResourceQuota] = None
    goal: Optional[str] = None


class ExecuteTaskRequest(BaseModel):
    """Request to execute a task with an agent."""
    agent_id: str
    task: str
    context: Optional[Dict[str, Any]] = None
    max_steps: Optional[int] = None


class TaskResult(BaseModel):
    """Result of a task execution."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    session_id: str
    status: str  # completed, failed, killed
    result: Optional[Any] = None
    steps_executed: int = 0
    tool_calls_made: int = 0
    violations_detected: int = 0
    corrections_applied: int = 0
    execution_time_sec: float = 0.0
    plan: Optional[ExecutionPlan] = None
    audit_events: List[str] = Field(default_factory=list)


# Forward reference resolution
AgentProfile.model_rebuild()
