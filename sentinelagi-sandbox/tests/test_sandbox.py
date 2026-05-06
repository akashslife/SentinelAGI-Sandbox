"""
Tests for Docker/gVisor Sandbox Manager.

Verifies container lifecycle management, code execution,
resource limits, and cleanup operations.
"""

import asyncio
import pytest
from unittest.mock import MagicMock, PropertyMock, patch

from sentinelagi.core.exceptions import (
    SandboxCreationError,
    SandboxExecutionError,
    SandboxTimeoutError,
)
from sentinelagi.sandbox.docker_manager import DockerSandboxManager


class TestDockerSandboxManager:
    """Test sandbox container management."""
    
    @pytest.fixture
    def manager(self):
        with patch("sentinelagi.sandbox.docker_manager.docker"):
            mgr = DockerSandboxManager()
            yield mgr
    
    @pytest.fixture
    def mock_container(self):
        """Create a mock container."""
        container = MagicMock()
        container.id = "container123"
        container.short_id = "abc123"
        container.stop = MagicMock()
        container.remove = MagicMock()
        
        exec_result = MagicMock()
        exec_result.exit_code = 0
        exec_result.output = (b"hello world", None)
        container.exec_run.return_value = exec_result
        
        return container
    
    @pytest.mark.asyncio
    async def test_create_sandbox(self, manager, mock_container):
        """Should create sandbox container."""
        with patch.object(manager, "client") as mock_client:
            mock_client.containers.run.return_value = mock_container
            
            container_id = await manager.create_sandbox("agent-001")
            
            assert container_id == "container123"
            assert manager._containers["agent-001"] == "container123"
            mock_client.containers.run.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_code(self, manager, mock_container):
        """Should execute code in sandbox."""
        manager._containers["agent-001"] = "container123"
        
        with patch.object(manager, "client") as mock_client:
            mock_client.containers.get.return_value = mock_container
            
            result = await manager.execute_code("agent-001", "print('hello')")
            
            assert result.success is True
            assert result.stdout == "hello world"
            assert result.exit_code == 0
    
    @pytest.mark.asyncio
    async def test_execute_command(self, manager, mock_container):
        """Should execute shell commands."""
        manager._containers["agent-001"] = "container123"
        
        with patch.object(manager, "client") as mock_client:
            mock_client.containers.get.return_value = mock_container
            
            result = await manager.execute_command(
                "agent-001", ["echo", "hello"]
            )
            
            assert result.success is True
            assert result.stdout == "hello world"
    
    @pytest.mark.asyncio
    async def test_kill_sandbox(self, manager, mock_container):
        """Should kill and remove sandbox."""
        manager._containers["agent-001"] = "container123"
        
        with patch.object(manager, "client") as mock_client:
            mock_client.containers.get.return_value = mock_container
            
            success = await manager.kill_sandbox("agent-001")
            
            assert success is True
            assert "agent-001" not in manager._containers
            mock_container.stop.assert_called_once()
            mock_container.remove.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_resource_usage(self, manager, mock_container):
        """Should get resource usage stats."""
        manager._containers["agent-001"] = "container123"
        
        mock_stats = {
            "cpu_stats": {
                "cpu_usage": {"total_usage": 1000000},
                "system_cpu_usage": 10000000,
            },
            "memory_stats": {"usage": 104857600},  # 100MB
        }
        mock_container.stats.return_value = mock_stats
        
        with patch.object(manager, "client") as mock_client:
            mock_client.containers.get.return_value = mock_container
            
            usage = await manager.get_resource_usage("agent-001")
            
            assert "cpu_percent" in usage
            assert "memory_mb" in usage
            assert usage["memory_mb"] == 100.0


class TestSandboxSecurity:
    """Test sandbox security configurations."""
    
    def test_default_security_options(self):
        """Sandbox should have secure defaults."""
        from sentinelagi.core.config import SandboxConfig
        
        config = SandboxConfig()
        assert config.network_mode == "none"
        assert config.enable_seccomp is True
        assert config.enable_apparmor is True
        assert config.read_only_rootfs is True
        assert config.no_new_privileges is True
        assert config.drop_capabilities == ["ALL"]
    
    def test_resource_limits_configured(self):
        """Resource limits should be set."""
        from sentinelagi.core.config import SandboxConfig
        
        config = SandboxConfig()
        assert config.memory_limit == "512m"
        assert config.cpu_quota == 1.0
        assert config.max_execution_time == 300
