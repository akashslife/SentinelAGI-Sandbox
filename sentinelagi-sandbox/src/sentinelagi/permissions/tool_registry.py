"""
Tool Registry

Central registry for all available tools with their schemas,
categories, and default permission templates.
"""

from typing import Any, Callable, Dict, List, Optional

from sentinelagi.core.models import ToolCategory, ToolPermission


class ToolDefinition:
    """Definition of an available tool."""
    
    def __init__(
        self,
        name: str,
        category: ToolCategory,
        description: str,
        parameters_schema: Dict[str, Any],
        handler: Optional[Callable] = None,
        requires_critic: bool = True,
        default_rate_limit: int = 60,
    ):
        self.name = name
        self.category = category
        self.description = description
        self.parameters_schema = parameters_schema
        self.handler = handler
        self.requires_critic = requires_critic
        self.default_rate_limit = default_rate_limit
    
    def to_permission(self, allowed: bool = True) -> ToolPermission:
        """Convert to a default permission."""
        return ToolPermission(
            tool_name=self.name,
            category=self.category,
            allowed=allowed,
            rate_limit=self.default_rate_limit,
            require_critic_review=self.requires_critic,
        )


class ToolRegistry:
    """Registry of all available tools."""
    
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()
    
    def _register_default_tools(self) -> None:
        """Register default available tools."""
        defaults = [
            # Web Search
            ToolDefinition(
                name="web_search",
                category=ToolCategory.WEB_SEARCH,
                description="Search the web for information",
                parameters_schema={
                    "query": {"type": "string", "required": True},
                    "max_results": {"type": "integer", "default": 5},
                },
                requires_critic=True,
                default_rate_limit=30,
            ),
            
            # Code Execution
            ToolDefinition(
                name="python_execute",
                category=ToolCategory.CODE_EXECUTION,
                description="Execute Python code in sandboxed environment",
                parameters_schema={
                    "code": {"type": "string", "required": True},
                    "timeout": {"type": "integer", "default": 30},
                    "memory_limit_mb": {"type": "integer", "default": 128},
                },
                requires_critic=True,
                default_rate_limit=20,
            ),
            
            ToolDefinition(
                name="bash_execute",
                category=ToolCategory.CODE_EXECUTION,
                description="Execute shell commands in sandboxed environment",
                parameters_schema={
                    "command": {"type": "string", "required": True},
                    "timeout": {"type": "integer", "default": 30},
                    "working_dir": {"type": "string", "default": "/tmp"},
                },
                requires_critic=True,
                default_rate_limit=10,
            ),
            
            # File I/O
            ToolDefinition(
                name="read_file",
                category=ToolCategory.FILE_IO,
                description="Read file contents",
                parameters_schema={
                    "path": {"type": "string", "required": True},
                    "limit_lines": {"type": "integer", "default": 1000},
                },
                requires_critic=True,
                default_rate_limit=100,
            ),
            
            ToolDefinition(
                name="write_file",
                category=ToolCategory.FILE_IO,
                description="Write content to a file",
                parameters_schema={
                    "path": {"type": "string", "required": True},
                    "content": {"type": "string", "required": True},
                    "append": {"type": "boolean", "default": False},
                },
                requires_critic=True,
                default_rate_limit=50,
            ),
            
            ToolDefinition(
                name="list_directory",
                category=ToolCategory.FILE_IO,
                description="List directory contents",
                parameters_schema={
                    "path": {"type": "string", "required": True},
                    "recursive": {"type": "boolean", "default": False},
                },
                requires_critic=False,
                default_rate_limit=100,
            ),
            
            # Network
            ToolDefinition(
                name="http_request",
                category=ToolCategory.NETWORK,
                description="Make HTTP requests",
                parameters_schema={
                    "url": {"type": "string", "required": True},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "default": {}},
                    "body": {"type": "string", "default": None},
                    "timeout": {"type": "integer", "default": 30},
                },
                requires_critic=True,
                default_rate_limit=30,
            ),
            
            # Data Analysis
            ToolDefinition(
                name="analyze_data",
                category=ToolCategory.DATA_ANALYSIS,
                description="Analyze data and compute statistics",
                parameters_schema={
                    "data": {"type": "string", "required": True},
                    "analysis_type": {"type": "string", "required": True},
                },
                requires_critic=False,
                default_rate_limit=50,
            ),
            
            # API Call
            ToolDefinition(
                name="api_call",
                category=ToolCategory.API_CALL,
                description="Call external APIs",
                parameters_schema={
                    "endpoint": {"type": "string", "required": True},
                    "method": {"type": "string", "default": "GET"},
                    "payload": {"type": "object", "default": {}},
                    "auth_token": {"type": "string", "default": None},
                },
                requires_critic=True,
                default_rate_limit=20,
            ),
        ]
        
        for tool in defaults:
            self.register(tool)
    
    def register(self, tool: ToolDefinition) -> None:
        """Register a new tool."""
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> Optional[ToolDefinition]:
        """Get tool by name."""
        return self._tools.get(name)
    
    def list_tools(
        self,
        category: Optional[ToolCategory] = None,
    ) -> List[ToolDefinition]:
        """List all tools, optionally filtered by category."""
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools
    
    def get_tool_names(self) -> List[str]:
        """Get all registered tool names."""
        return list(self._tools.keys())
    
    def create_permission_template(
        self,
        tool_names: List[str],
        allow_others: bool = False,
    ) -> List[ToolPermission]:
        """
        Create a permission set for specified tools.
        
        Args:
            tool_names: List of tool names to include
            allow_others: If False, unspecified tools are denied
        """
        permissions = []
        
        for name in tool_names:
            tool = self._tools.get(name)
            if tool:
                permissions.append(tool.to_permission(allowed=True))
        
        if not allow_others:
            # Add deny-all for unlisted tools
            for name, tool in self._tools.items():
                if name not in tool_names:
                    permissions.append(ToolPermission(
                        tool_name=name,
                        category=tool.category,
                        allowed=False,
                    ))
        
        return permissions


# Singleton
tool_registry = ToolRegistry()
