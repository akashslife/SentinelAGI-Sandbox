"""
SentinelAGI Sandbox - Main Entry Point

Command-line interface for running the containment system.
"""

import argparse
import asyncio
import logging
import sys

from sentinelagi.api.app import create_app
from sentinelagi.core.config import get_settings
from sentinelagi.core.models import (
    AgentProfile,
    CreateAgentRequest,
    ResourceQuota,
    ToolPermission,
)
from sentinelagi.permissions.tool_registry import tool_registry

logger = logging.getLogger(__name__)


def setup_logging():
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, get_settings().log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SentinelAGI Sandbox - Autonomous Agent Containment System",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Server command
    server_parser = subparsers.add_parser("server", help="Run API server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    server_parser.add_argument("--port", type=int, default=8000, help="Bind port")
    server_parser.add_argument("--reload", action="store_true", help="Auto-reload")
    
    # Quickstart command
    subparsers.add_parser("quickstart", help="Run a quick demo")
    
    # Status command
    subparsers.add_parser("status", help="Check system status")
    
    # Cleanup command
    subparsers.add_parser("cleanup", help="Clean up all sandboxes")
    
    return parser.parse_args()


async def run_quickstart():
    """Run a quick demo of the containment system."""
    from sentinelagi.agents.orchestrator import orchestrator
    from sentinelagi.permissions.tool_registry import tool_registry
    
    logger.info("=" * 60)
    logger.info("SentinelAGI Sandbox - Quickstart Demo")
    logger.info("=" * 60)
    
    # Create an agent with limited permissions
    logger.info("\n[1] Creating agent with scoped permissions...")
    
    permissions = tool_registry.create_permission_template([
        "python_execute",
        "web_search",
        "read_file",
    ])
    
    profile = AgentProfile(
        name="demo_agent",
        description="Demo agent with limited tool access",
        permissions=permissions,
        resource_quota=ResourceQuota(
            max_cpu_cores=0.5,
            max_memory_mb=256,
            max_execution_time_sec=60,
        ),
    )
    
    agent = await orchestrator.create_agent(profile)
    logger.info(f"   Created agent: {agent.agent_id}")
    logger.info(f"   Permissions: {[p.tool_name + ': ' + str(p.allowed) for p in permissions[:3]]}")
    
    # Execute a safe task
    logger.info("\n[2] Executing safe task (Python calculation)...")
    result = await orchestrator.execute_task(
        agent_id=agent.agent_id,
        task="Calculate the factorial of 5 using Python",
    )
    logger.info(f"   Status: {result.status}")
    logger.info(f"   Steps: {result.steps_executed}")
    logger.info(f"   Time: {result.execution_time_sec:.2f}s")
    if result.result:
        logger.info(f"   Result: {result.result[:200]}...")
    
    # Show that unauthorized tools are blocked
    logger.info("\n[3] Demonstrating permission enforcement...")
    logger.info("   Agent only has: python_execute, web_search, read_file")
    logger.info("   Attempting to use 'bash_execute' (should be blocked)...")
    
    # Execute a task that might try unauthorized tools
    result2 = await orchestrator.execute_task(
        agent_id=agent.agent_id,
        task="List all files in /etc using bash",
    )
    logger.info(f"   Status: {result2.status}")
    logger.info(f"   Violations detected: {result2.violations_detected}")
    
    # Cleanup
    logger.info("\n[4] Cleaning up...")
    await orchestrator.kill_agent(agent.agent_id)
    logger.info("   Agent terminated")
    
    logger.info("\n" + "=" * 60)
    logger.info("Demo complete!")
    logger.info("=" * 60)


async def check_status():
    """Check system status."""
    from sentinelagi.monitoring.audit_logger import audit_logger
    from sentinelagi.monitoring.alert_manager import alert_manager
    from sentinelagi.sandbox.docker_manager import sandbox_manager
    
    logger.info("SentinelAGI System Status")
    logger.info("-" * 40)
    
    # Check Docker
    try:
        client = sandbox_manager.client
        info = client.info()
        logger.info(f"Docker: Connected ({info.get('ServerVersion', 'unknown')})")
        logger.info(f"  Runtime: {info.get('DefaultRuntime', 'unknown')}")
        logger.info(f"  Containers: {client.info().get('Containers', 'unknown')}")
    except Exception as e:
        logger.warning(f"Docker: {e}")
    
    # Check Redis
    audit_health = await audit_logger.health_check()
    logger.info(f"Audit Logger: {audit_health['status']} ({audit_health['mode']})")
    
    # Alert summary
    alert_summary = alert_manager.get_alert_summary()
    logger.info(f"Alerts: {alert_summary.get('total_alerts', 0)} total")


async def run_cleanup():
    """Run cleanup of all sandboxes."""
    from sentinelagi.sandbox.docker_manager import sandbox_manager
    
    logger.info("Cleaning up all sandbox containers...")
    count = await sandbox_manager.cleanup_all()
    logger.info(f"Removed {count} containers")


def main():
    """Main entry point."""
    setup_logging()
    args = parse_args()
    
    if args.command == "server":
        import uvicorn
        
        logger.info(f"Starting server on {args.host}:{args.port}")
        uvicorn.run(
            "sentinelagi.api.app:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
        )
    
    elif args.command == "quickstart":
        asyncio.run(run_quickstart())
    
    elif args.command == "status":
        asyncio.run(check_status())
    
    elif args.command == "cleanup":
        asyncio.run(run_cleanup())
    
    else:
        # Default: print help
        parse_args()


if __name__ == "__main__":
    main()
