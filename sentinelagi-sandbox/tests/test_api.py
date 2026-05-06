"""
Tests for FastAPI endpoints.

Integration tests for the REST API covering agent management,
task execution, and monitoring endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

from sentinelagi.api.app import create_app


@pytest.fixture
def client():
    """Create test client."""
    app = create_app()
    return TestClient(app)


class TestHealthEndpoints:
    """Test health and status endpoints."""
    
    def test_root_endpoint(self, client):
        """Root should return system info."""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert data["name"] == "SentinelAGI Sandbox"
        assert "version" in data
        assert data["status"] == "operational"
    
    def test_health_check(self, client):
        """Health endpoint should return component status."""
        with patch("sentinelagi.api.routes.audit_logger.health_check") as mock_health:
            mock_health.return_value = {
                "status": "healthy",
                "mode": "redis",
                "redis_connected": True,
            }
            
            response = client.get("/api/v1/health")
            assert response.status_code == 200
            
            data = response.json()
            assert data["status"] == "healthy"
            assert "components" in data


class TestAgentEndpoints:
    """Test agent management endpoints."""
    
    def test_list_agents_empty(self, client):
        """Should return empty list when no agents."""
        with patch("sentinelagi.api.routes.orchestrator.list_agents") as mock_list:
            mock_list.return_value = []
            
            response = client.get("/api/v1/agents")
            assert response.status_code == 200
            assert response.json() == []
    
    def test_create_agent(self, client):
        """Should create agent with permissions."""
        from sentinelagi.core.models import AgentProfile
        
        mock_agent = MagicMock(spec=AgentProfile)
        mock_agent.agent_id = "agent-123"
        mock_agent.name = "test_agent"
        mock_agent.permissions = []
        mock_agent.created_at = MagicMock()
        mock_agent.created_at.isoformat.return_value = "2024-01-01T00:00:00"
        
        with patch("sentinelagi.api.routes.orchestrator.create_agent") as mock_create:
            mock_create.return_value = mock_agent
            
            response = client.post("/api/v1/agents", json={
                "name": "test_agent",
                "description": "Test agent",
            })
            
            assert response.status_code == 201
            data = response.json()
            assert data["agent_id"] == "agent-123"
            assert data["name"] == "test_agent"
    
    def test_get_agent_not_found(self, client):
        """Should return 404 for unknown agent."""
        with patch("sentinelagi.api.routes.orchestrator.list_agents") as mock_list:
            mock_list.return_value = []
            
            response = client.get("/api/v1/agents/nonexistent")
            assert response.status_code == 404
    
    def test_delete_agent(self, client):
        """Should delete agent."""
        with patch("sentinelagi.api.routes.orchestrator.kill_agent") as mock_kill:
            mock_kill.return_value = True
            
            response = client.delete("/api/v1/agents/agent-123")
            assert response.status_code == 200
            assert "terminated" in response.json()["message"]


class TestToolEndpoints:
    """Test tool registry endpoints."""
    
    def test_list_tools(self, client):
        """Should list available tools."""
        response = client.get("/api/v1/tools")
        assert response.status_code == 200
        
        tools = response.json()
        assert isinstance(tools, list)
        assert len(tools) > 0
        
        # Should include expected tools
        tool_names = [t["name"] for t in tools]
        assert "python_execute" in tool_names
        assert "web_search" in tool_names
    
    def test_list_tools_by_category(self, client):
        """Should filter tools by category."""
        response = client.get("/api/v1/tools?category=code_execution")
        assert response.status_code == 200
        
        tools = response.json()
        for tool in tools:
            assert tool["category"] == "code_execution"


class TestMITREEndpoints:
    """Test MITRE ATLAS endpoints."""
    
    def test_list_techniques(self, client):
        """Should list MITRE techniques."""
        response = client.get("/api/v1/mitre/techniques")
        assert response.status_code == 200
        
        techniques = response.json()
        assert isinstance(techniques, list)
        assert len(techniques) > 0
    
    def test_get_technique(self, client):
        """Should get specific technique."""
        response = client.get("/api/v1/mitre/techniques/AML.T0015")
        assert response.status_code == 200
        
        technique = response.json()
        assert technique["technique_id"] == "AML.T0015"
        assert "name" in technique
        assert "mitigations" in technique
    
    def test_get_technique_not_found(self, client):
        """Should return 404 for unknown technique."""
        response = client.get("/api/v1/mitre/techniques/AML.T9999")
        assert response.status_code == 404
    
    def test_mitre_statistics(self, client):
        """Should return MITRE statistics."""
        response = client.get("/api/v1/mitre/statistics")
        assert response.status_code == 200
        
        stats = response.json()
        assert "total_techniques_mapped" in stats
        assert "severity_distribution" in stats


class TestAuditEndpoints:
    """Test audit and monitoring endpoints."""
    
    def test_get_audit_events(self, client):
        """Should return audit events."""
        with patch("sentinelagi.api.routes.audit_logger.get_recent_events") as mock_get:
            mock_get.return_value = []
            
            response = client.get("/api/v1/audit/events")
            assert response.status_code == 200
            assert response.json() == []
    
    def test_get_audit_statistics(self, client):
        """Should return audit statistics."""
        with patch("sentinelagi.api.routes.audit_logger.get_event_statistics") as mock_stats:
            mock_stats.return_value = {
                "total_events": 100,
                "consumer_groups": 0,
            }
            
            response = client.get("/api/v1/audit/statistics")
            assert response.status_code == 200
            assert response.json()["total_events"] == 100
    
    def test_get_alerts(self, client):
        """Should return alert summary."""
        with patch("sentinelagi.api.routes.alert_manager.get_alert_summary") as mock_summary:
            mock_summary.return_value = {
                "total_alerts": 5,
                "affected_agents": 2,
            }
            
            response = client.get("/api/v1/alerts")
            assert response.status_code == 200
            assert response.json()["total_alerts"] == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
