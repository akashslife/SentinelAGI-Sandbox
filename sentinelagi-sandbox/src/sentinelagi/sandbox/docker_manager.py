"""
Docker/gVisor Sandbox Manager

Manages isolated container environments using Docker with optional
gVisor (runsc) runtime for defense-in-depth isolation of
code execution environments.
"""

import asyncio
import json
import logging
import os
import tempfile
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import docker
from docker.errors import DockerException, NotFound

from sentinelagi.core.config import get_settings
from sentinelagi.core.exceptions import (
    SandboxCreationError,
    SandboxExecutionError,
    SandboxResourceError,
    SandboxTimeoutError,
)

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of sandboxed code execution."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time_sec: float
    memory_usage_mb: float = 0.0
    truncated: bool = False


class DockerSandboxManager:
    """Manages Docker containers with gVisor isolation."""
    
    def __init__(self):
        self.config = get_settings().sandbox
        self._client: Optional[docker.DockerClient] = None
        self._containers: Dict[str, str] = {}  # agent_id -> container_id
        self._semaphore = asyncio.Semaphore(10)  # Limit concurrent sandboxes
    
    @property
    def client(self) -> docker.DockerClient:
        """Lazy initialization of Docker client."""
        if self._client is None:
            try:
                self._client = docker.from_env()
                # Verify connection
                self._client.ping()
                logger.info(f"Docker connected. Version: {self._client.version()['Version']}")
            except DockerException as e:
                logger.error(f"Failed to connect to Docker: {e}")
                raise SandboxCreationError(
                    f"Docker connection failed: {e}",
                    details={"error": str(e)},
                )
        return self._client
    
    def _get_runtime(self) -> str:
        """Determine container runtime (gVisor or default)."""
        if self.config.runtime == "runsc":
            # Check if gVisor/runsc is available
            try:
                runtimes = self.client.info().get("Runtimes", {})
                if "runsc" in runtimes:
                    logger.info("Using gVisor (runsc) runtime")
                    return "runsc"
                else:
                    logger.warning("gVisor (runsc) not available, falling back to default runtime")
                    return self.client.info().get("DefaultRuntime", "runc")
            except Exception as e:
                logger.warning(f"Could not detect runtimes: {e}, using default")
                return "runc"
        return self.config.runtime
    
    def _create_container_config(
        self,
        agent_id: str,
        command: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create container configuration with security options."""
        command = command or ["sleep", str(self.config.max_execution_time)]
        
        # Security options for defense in depth
        security_opt = []
        if self.config.enable_seccomp:
            security_opt.append("seccomp=default")
        if self.config.enable_apparmor:
            security_opt.append("apparmor=docker-default")
        
        # Capabilities
        cap_drop = self.config.drop_capabilities
        cap_add = self.config.add_capabilities
        
        return {
            "image": self.config.image,
            "command": command,
            "runtime": self._get_runtime(),
            "network_mode": self.config.network_mode,
            "mem_limit": self.config.memory_limit,
            "memswap_limit": self.config.memory_limit,  # Prevent swap usage
            "cpu_quota": int(self.config.cpu_quota * 100000),  # Microseconds
            "cpu_period": 100000,
            "storage_opt": {"size": self.config.storage_limit},
            "security_opt": security_opt,
            "cap_drop": cap_drop,
            "cap_add": cap_add,
            "read_only": self.config.read_only_rootfs,
            "no_new_privileges": self.config.no_new_privileges,
            "user": "1000:1000",  # Run as non-root
            "environment": {
                "AGENT_ID": agent_id,
                "SANDBOX": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
            },
            "labels": {
                "sentinelagi.agent_id": agent_id,
                "sentinelagi.managed": "true",
                "sentinelagi.created": str(asyncio.get_event_loop().time()),
            },
            "stdin_open": True,
            "detach": True,
        }
    
    async def create_sandbox(
        self,
        agent_id: str,
        command: Optional[List[str]] = None,
    ) -> str:
        """
        Create a new sandbox container for an agent.
        
        Returns:
            Container ID
        """
        async with self._semaphore:
            try:
                loop = asyncio.get_event_loop()
                
                config = self._create_container_config(agent_id, command)
                
                container = await loop.run_in_executor(
                    None,
                    lambda: self.client.containers.run(**config),
                )
                
                self._containers[agent_id] = container.id
                logger.info(f"Created sandbox container {container.short_id} for agent {agent_id}")
                
                return container.id
            
            except DockerException as e:
                logger.error(f"Failed to create sandbox: {e}")
                raise SandboxCreationError(
                    f"Sandbox creation failed: {e}",
                    details={"agent_id": agent_id, "error": str(e)},
                )
    
    async def execute_code(
        self,
        agent_id: str,
        code: str,
        language: str = "python",
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """
        Execute code in sandboxed container.
        
        Args:
            agent_id: Agent requesting execution
            code: Code to execute
            language: Programming language
            timeout: Execution timeout in seconds
        
        Returns:
            ExecutionResult with output and metadata
        """
        timeout = timeout or self.config.max_execution_time
        container_id = self._containers.get(agent_id)
        
        if not container_id:
            # Create sandbox on-demand
            container_id = await self.create_sandbox(agent_id)
        
        try:
            container = self.client.containers.get(container_id)
            
            # Create temp file with code
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code)
                temp_path = f.name
            
            try:
                # Copy code into container
                with open(temp_path, 'rb') as f:
                    code_bytes = f.read()
                
                # Execute code via exec_run
                exec_command = ["python", "-c", code]
                
                loop = asyncio.get_event_loop()
                
                # Run with timeout
                start_time = asyncio.get_event_loop().time()
                
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: container.exec_run(
                            exec_command,
                            demux=True,
                            tty=False,
                            user="1000",
                            workdir="/tmp",
                            environment={"HOME": "/tmp"},
                        ),
                    ),
                    timeout=timeout,
                )
                
                execution_time = asyncio.get_event_loop().time() - start_time
                
                stdout = ""
                stderr = ""
                
                if result.output:
                    stdout_bytes, stderr_bytes = result.output
                    stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
                    stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
                
                return ExecutionResult(
                    success=result.exit_code == 0,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=result.exit_code,
                    execution_time_sec=execution_time,
                    truncated=len(stdout) > 100000 or len(stderr) > 100000,
                )
            
            finally:
                os.unlink(temp_path)
        
        except asyncio.TimeoutError:
            logger.warning(f"Code execution timed out for agent {agent_id}")
            await self.kill_sandbox(agent_id)
            raise SandboxTimeoutError(
                f"Execution exceeded {timeout}s timeout",
                details={"agent_id": agent_id, "timeout": timeout},
            )
        
        except DockerException as e:
            logger.error(f"Code execution failed: {e}")
            raise SandboxExecutionError(
                f"Execution failed: {e}",
                details={"agent_id": agent_id, "error": str(e)},
            )
    
    async def execute_command(
        self,
        agent_id: str,
        command: List[str],
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """Execute a shell command in the sandbox."""
        timeout = timeout or self.config.max_execution_time
        container_id = self._containers.get(agent_id)
        
        if not container_id:
            container_id = await self.create_sandbox(agent_id)
        
        try:
            container = self.client.containers.get(container_id)
            
            loop = asyncio.get_event_loop()
            start_time = asyncio.get_event_loop().time()
            
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: container.exec_run(
                        command,
                        demux=True,
                        tty=False,
                        user="1000",
                        workdir="/tmp",
                    ),
                ),
                timeout=timeout,
            )
            
            execution_time = asyncio.get_event_loop().time() - start_time
            
            stdout = ""
            stderr = ""
            
            if result.output:
                stdout_bytes, stderr_bytes = result.output
                stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
                stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
            
            return ExecutionResult(
                success=result.exit_code == 0,
                stdout=stdout,
                stderr=stderr,
                exit_code=result.exit_code,
                execution_time_sec=execution_time,
            )
        
        except asyncio.TimeoutError:
            logger.warning(f"Command timed out for agent {agent_id}")
            await self.kill_sandbox(agent_id)
            raise SandboxTimeoutError(
                f"Command exceeded {timeout}s timeout",
                details={"agent_id": agent_id, "command": command},
            )
        
        except DockerException as e:
            logger.error(f"Command execution failed: {e}")
            raise SandboxExecutionError(
                f"Command failed: {e}",
                details={"agent_id": agent_id, "command": command},
            )
    
    async def kill_sandbox(self, agent_id: str) -> bool:
        """Kill and remove sandbox container for an agent."""
        container_id = self._containers.pop(agent_id, None)
        
        if not container_id:
            return False
        
        try:
            loop = asyncio.get_event_loop()
            container = self.client.containers.get(container_id)
            
            await loop.run_in_executor(None, container.stop, 5)
            await loop.run_in_executor(None, container.remove, True)
            
            logger.info(f"Killed sandbox for agent {agent_id}")
            return True
        
        except NotFound:
            logger.debug(f"Container already removed for agent {agent_id}")
            return True
        except DockerException as e:
            logger.error(f"Failed to kill sandbox: {e}")
            return False
    
    async def get_resource_usage(self, agent_id: str) -> Dict[str, float]:
        """Get current resource usage for a sandbox."""
        container_id = self._containers.get(agent_id)
        if not container_id:
            return {"cpu_percent": 0.0, "memory_mb": 0.0}
        
        try:
            loop = asyncio.get_event_loop()
            container = self.client.containers.get(container_id)
            
            stats = await loop.run_in_executor(None, container.stats, False)
            
            cpu_stats = stats.get("cpu_stats", {})
            memory_stats = stats.get("memory_stats", {})
            
            cpu_usage = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            system_cpu = cpu_stats.get("system_cpu_usage", 1)
            cpu_percent = (cpu_usage / system_cpu) * 100 if system_cpu > 0 else 0
            
            memory_mb = memory_stats.get("usage", 0) / (1024 * 1024)
            
            return {
                "cpu_percent": round(cpu_percent, 2),
                "memory_mb": round(memory_mb, 2),
            }
        
        except Exception as e:
            logger.error(f"Failed to get resource usage: {e}")
            return {"cpu_percent": 0.0, "memory_mb": 0.0}
    
    async def cleanup_all(self) -> int:
        """Clean up all managed sandbox containers. Returns count of removed."""
        count = 0
        
        for agent_id in list(self._containers.keys()):
            if await self.kill_sandbox(agent_id):
                count += 1
        
        # Also clean up any orphaned sentinelagi containers
        try:
            loop = asyncio.get_event_loop()
            containers = self.client.containers.list(
                filters={"label": "sentinelagi.managed=true"},
                all=True,
            )
            for container in containers:
                try:
                    await loop.run_in_executor(None, container.stop, 1)
                    await loop.run_in_executor(None, container.remove, True)
                    count += 1
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        
        return count


# Singleton
sandbox_manager = DockerSandboxManager()
