"""
SentinelAGI Custom Exceptions

Hierarchical exception structure for granular error handling across
the containment system.
"""

from enum import Enum
from typing import Any, Dict, Optional


class SeverityLevel(Enum):
    """Incident severity classification aligned with MITRE ATLAS."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SentinelAGIError(Exception):
    """Base exception for all SentinelAGI errors."""
    
    def __init__(
        self,
        message: str,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.details = details or {}
        self.error_code = error_code or "SENTINEL_UNKNOWN"


# Sandbox Exceptions
class SandboxError(SentinelAGIError):
    """Container sandbox related errors."""
    pass


class SandboxCreationError(SandboxError):
    """Failed to create sandbox container."""
    pass


class SandboxExecutionError(SandboxError):
    """Code execution within sandbox failed."""
    pass


class SandboxTimeoutError(SandboxError):
    """Sandbox execution exceeded time limit."""
    pass


class SandboxResourceError(SandboxError):
    """Sandbox resource limit exceeded."""
    pass


# Permission & Security Exceptions
class PermissionError(SentinelAGIError):
    """Tool permission or authorization errors."""
    pass


class ToolNotAuthorizedError(PermissionError):
    """Agent attempted to use unauthorized tool."""
    pass


class PrivilegeEscalationError(PermissionError):
    """Detected potential privilege escalation attempt."""
    pass


class PolicyViolationError(PermissionError):
    """Constitutional AI policy violation detected."""
    pass


class ScopeViolationError(PermissionError):
    """Agent attempted action outside declared scope."""
    pass


# Agent Orchestration Exceptions
class OrchestrationError(SentinelAGIError):
    """Multi-agent orchestration errors."""
    pass


class AgentNotFoundError(OrchestrationError):
    """Requested agent not found."""
    pass


class MaxAgentsExceededError(OrchestrationError):
    """Maximum concurrent agents limit reached."""
    pass


class PlanExecutionError(OrchestrationError):
    """Multi-step plan execution failed."""
    pass


class CorrectionLimitExceededError(OrchestrationError):
    """Maximum self-correction attempts exceeded."""
    pass


# Monitoring & Audit Exceptions
class MonitoringError(SentinelAGIError):
    """Audit logging and monitoring errors."""
    pass


class AuditLogError(MonitoringError):
    """Failed to write or read audit log."""
    pass


class AlertDispatchError(MonitoringError):
    """Failed to dispatch security alert."""
    pass


# MITRE ATLAS Exceptions
class MITREMappingError(SentinelAGIError):
    """MITRE ATLAS framework mapping errors."""
    pass
