"""
FastAPI Routes

REST API endpoints for agent management, task execution,
monitoring, and audit log access.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from sentinelagi.agents.orchestrator import orchestrator
from sentinelagi.core.config import get_settings
from sentinelagi.core.exceptions import (
    CorrectionLimitExceededError,
    MaxAgentsExceededError,
    ToolNotAuthorizedError,
)
from sentinelagi.core.models import (
    AgentProfile,
    AgentStatus,
    CreateAgentRequest,
    ExecuteTaskRequest,
    ResourceQuota,
    TaskResult,
    ToolPermission,
)
from sentinelagi.monitoring.alert_manager import alert_manager
from sentinelagi.monitoring.audit_logger import audit_logger
from sentinelagi.permissions.manager import permission_manager
from sentinelagi.permissions.mitre_atlas import mitre_mapper
from sentinelagi.permissions.tool_registry import tool_registry
from sentinelagi.sandbox.docker_manager import sandbox_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


# ==================== Agent Management ====================

@router.post("/agents", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_agent(request: CreateAgentRequest):
    """Create a new agent with specified permissions."""
    try:
        # Build resource quota
        quota = request.resource_quota or ResourceQuota()
        
        # Build permissions from tool names if provided
        permissions = request.permissions
        if not permissions and hasattr(request, 'allowed_tools'):
            permissions = tool_registry.create_permission_template(request.allowed_tools)
        
        profile = AgentProfile(
            name=request.name,
            description=request.description,
            permissions=permissions,
            resource_quota=quota,
        )
        
        result = await orchestrator.create_agent(profile)
        
        return {
            "agent_id": result.agent_id,
            "name": result.name,
            "permissions": [
                {"tool": p.tool_name, "allowed": p.allowed}
                for p in result.permissions
            ],
            "created_at": result.created_at.isoformat(),
        }
    
    except MaxAgentsExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=e.message,
        )
    except Exception as e:
        logger.error(f"Failed to create agent: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get("/agents", response_model=List[Dict[str, Any]])
async def list_agents():
    """List all active agents."""
    agents = orchestrator.list_agents()
    return [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "status": orchestrator.get_agent_status(a.agent_id),
            "created_at": a.created_at.isoformat(),
        }
        for a in agents
    ]


@router.get("/agents/{agent_id}", response_model=Dict[str, Any])
async def get_agent(agent_id: str):
    """Get agent details and status."""
    agents = orchestrator.list_agents()
    agent = next((a for a in agents if a.agent_id == agent_id), None)
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )
    
    status_info = orchestrator.get_agent_status(agent_id)
    violations = permission_manager.get_violation_summary(agent_id)
    
    return {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "description": agent.description,
        "permissions": [
            {"tool": p.tool_name, "allowed": p.allowed, "category": p.category.value}
            for p in agent.permissions
        ],
        "resource_quota": agent.resource_quota.model_dump(),
        "status": status_info.model_dump() if status_info else None,
        "violation_summary": violations,
        "created_at": agent.created_at.isoformat(),
    }


@router.delete("/agents/{agent_id}", status_code=status.HTTP_204_204)
async def delete_agent(agent_id: str):
    """Kill and remove an agent."""
    success = await orchestrator.kill_agent(agent_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )
    return {"message": f"Agent {agent_id} terminated"}


# ==================== Task Execution ====================

@router.post("/tasks/execute", response_model=TaskResult)
async def execute_task(request: ExecuteTaskRequest):
    """Execute a task with an agent."""
    try:
        result = await orchestrator.execute_task(
            agent_id=request.agent_id,
            task=request.task,
        )
        return result
    
    except ToolNotAuthorizedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": e.message,
                "mitre_techniques": e.details.get("mitre_techniques", []),
            },
        )
    except CorrectionLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=e.message,
        )
    except Exception as e:
        logger.error(f"Task execution failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# ==================== Tool Registry ====================

@router.get("/tools", response_model=List[Dict[str, Any]])
async def list_tools(category: Optional[str] = None):
    """List all available tools."""
    from sentinelagi.core.models import ToolCategory
    
    cat = None
    if category:
        try:
            cat = ToolCategory(category)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid category: {category}",
            )
    
    tools = tool_registry.list_tools(category=cat)
    return [
        {
            "name": t.name,
            "category": t.category.value,
            "description": t.description,
            "parameters_schema": t.parameters_schema,
            "requires_critic": t.requires_critic,
            "default_rate_limit": t.default_rate_limit,
        }
        for t in tools
    ]


# ==================== Monitoring & Audit ====================

@router.get("/audit/events", response_model=List[Dict[str, Any]])
async def get_audit_events(
    count: int = Query(100, ge=1, le=1000),
    agent_id: Optional[str] = None,
):
    """Get recent audit events."""
    events = await audit_logger.get_recent_events(count=count, agent_id=agent_id)
    return [e.model_dump() for e in events]


@router.get("/audit/statistics", response_model=Dict[str, Any])
async def get_audit_statistics():
    """Get audit stream statistics."""
    return await audit_logger.get_event_statistics()


@router.get("/alerts", response_model=Dict[str, Any])
async def get_alerts(agent_id: Optional[str] = None):
    """Get security alerts summary."""
    if agent_id:
        history = alert_manager.get_agent_alert_history(agent_id)
        return {
            "agent_id": agent_id,
            "alerts": [a.model_dump() for a in history],
        }
    
    return alert_manager.get_alert_summary()


@router.get("/health", response_model=Dict[str, Any])
async def health_check():
    """System health check endpoint."""
    audit_health = await audit_logger.health_check()
    
    return {
        "status": "healthy",
        "version": get_settings().app_version,
        "environment": get_settings().environment,
        "components": {
            "api": "healthy",
            "audit_logger": audit_health,
            "orchestrator": "healthy" if orchestrator._graph else "unhealthy",
        },
    }


# ==================== MITRE ATLAS ====================

@router.get("/mitre/techniques", response_model=List[Dict[str, Any]])
async def list_mitre_techniques():
    """List all mapped MITRE ATLAS techniques."""
    techniques = mitre_mapper.get_all_techniques()
    return [
        {
            "technique_id": t.technique_id,
            "name": t.name,
            "description": t.description,
            "tactics": t.tactics,
            "severity": t.severity,
        }
        for t in techniques
    ]


@router.get("/mitre/techniques/{technique_id}", response_model=Dict[str, Any])
async def get_mitre_technique(technique_id: str):
    """Get details of a specific MITRE ATLAS technique."""
    technique = mitre_mapper.get_technique(technique_id)
    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found",
        )
    
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "description": technique.description,
        "tactics": technique.tactics,
        "tool_categories": [c.value for c in technique.tool_categories],
        "severity": technique.severity,
        "indicators": technique.indicators,
        "mitigations": technique.mitigations,
    }


@router.get("/mitre/statistics", response_model=Dict[str, Any])
async def get_mitre_statistics():
    """Get MITRE ATLAS coverage statistics."""
    return {
        "total_techniques_mapped": len(mitre_mapper.get_all_techniques()),
        "severity_distribution": mitre_mapper.get_severity_distribution(),
        "coverage_by_category": {},
    }


# ==================== Sandbox Management ====================

@router.post("/sandbox/{agent_id}/create", response_model=Dict[str, Any])
async def create_sandbox(agent_id: str):
    """Create a sandbox container for an agent."""
    try:
        container_id = await sandbox_manager.create_sandbox(agent_id)
        return {
            "agent_id": agent_id,
            "container_id": container_id,
            "status": "created",
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.delete("/sandbox/{agent_id}", status_code=status.HTTP_200_OK)
async def kill_sandbox(agent_id: str):
    """Kill sandbox container for an agent."""
    success = await sandbox_manager.kill_sandbox(agent_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No sandbox found for agent {agent_id}",
        )
    return {"message": f"Sandbox for agent {agent_id} terminated"}


@router.get("/sandbox/{agent_id}/resources", response_model=Dict[str, float])
async def get_sandbox_resources(agent_id: str):
    """Get resource usage for a sandbox."""
    return await sandbox_manager.get_resource_usage(agent_id)


@router.post("/sandbox/cleanup", response_model=Dict[str, Any])
async def cleanup_all_sandboxes():
    """Clean up all sandbox containers."""
    count = await sandbox_manager.cleanup_all()
    return {"removed_containers": count}


# ==================== Permission Management ====================

@router.get("/permissions/{agent_id}", response_model=Dict[str, Any])
async def get_agent_permissions(agent_id: str):
    """Get permission summary for an agent."""
    summary = permission_manager.get_violation_summary(agent_id)
    agents = orchestrator.list_agents()
    agent = next((a for a in agents if a.agent_id == agent_id), None)
    
    return {
        "agent_id": agent_id,
        "permissions": [
            {
                "tool": p.tool_name,
                "allowed": p.allowed,
                "category": p.category.value,
                "rate_limit": p.rate_limit,
            }
            for p in (agent.permissions if agent else [])
        ],
        "violation_summary": summary,
    }
