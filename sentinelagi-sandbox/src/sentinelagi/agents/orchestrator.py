"""
LangGraph Multi-Agent Orchestrator

Implements a stateful multi-agent system using LangGraph where:
- Planner agent decomposes goals into step-by-step plans
- Executor agent carries out each step using sandboxed tools
- Critic agent reviews outputs before they are committed
- The system supports self-correction loops and long-horizon planning
"""

import json
import logging
import time
import uuid
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from sentinelagi.agents.critic import critic
from sentinelagi.core.config import get_settings
from sentinelagi.core.exceptions import (
    CorrectionLimitExceededError,
    MaxAgentsExceededError,
    PlanExecutionError,
    ToolNotAuthorizedError,
)
from sentinelagi.core.models import (
    AgentProfile,
    AgentState as AgentStateEnum,
    AgentStatus,
    AuditEvent,
    ExecutionPlan,
    PlanStep,
    TaskResult,
    ToolCall,
)
from sentinelagi.monitoring.audit_logger import audit_logger
from sentinelagi.permissions.manager import permission_manager
from sentinelagi.sandbox.docker_manager import sandbox_manager

logger = logging.getLogger(__name__)


# ==================== LangGraph State ====================

class AgentGraphState(TypedDict):
    """State maintained across the LangGraph execution."""
    messages: Annotated[list, add_messages]
    agent_id: str
    session_id: str
    goal: str
    plan: Optional[ExecutionPlan]
    current_step_index: int
    step_results: List[Dict[str, Any]]
    corrections_count: int
    violations_count: int
    tool_calls: List[ToolCall]
    status: str  # pending, planning, executing, critiquing, correcting, completed, failed
    final_result: Optional[str]
    execution_start: float
    metadata: Dict[str, Any]


# ==================== Orchestrator ====================

class LangGraphOrchestrator:
    """LangGraph-based multi-agent orchestration system."""
    
    def __init__(self):
        self.config = get_settings().agent
        self.security = get_settings().security
        self.active_agents: Dict[str, AgentProfile] = {}
        self.agent_status: Dict[str, AgentStatus] = {}
        self._graph = self._build_graph()
    
    def _init_llm(self, model: Optional[str] = None) -> ChatOpenAI:
        """Initialize LLM for agent use."""
        return ChatOpenAI(
            model=model or self.config.planner_model,
            temperature=self.config.temperature,
            max_tokens=4000,
        )
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine for agent execution."""
        
        # Define the workflow graph
        workflow = StateGraph(AgentGraphState)
        
        # Add nodes
        workflow.add_node("planner", self._planning_node)
        workflow.add_node("executor", self._execution_node)
        workflow.add_node("critic", self._critic_node)
        workflow.add_node("corrector", self._correction_node)
        workflow.add_node("finalizer", self._finalization_node)
        
        # Define edges
        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "executor")
        workflow.add_edge("executor", "critic")
        
        # Conditional routing from critic
        workflow.add_conditional_edges(
            "critic",
            self._critic_router,
            {
                "correct": "corrector",
                "continue": "executor",
                "finalize": "finalizer",
            },
        )
        
        workflow.add_edge("corrector", "executor")
        workflow.add_edge("finalizer", END)
        
        return workflow.compile()
    
    # ==================== Graph Nodes ====================
    
    async def _planning_node(self, state: AgentGraphState) -> AgentGraphState:
        """Planner agent: Decompose goal into steps."""
        agent_id = state["agent_id"]
        goal = state["goal"]
        
        logger.info(f"[Agent {agent_id}] Planning for goal: {goal}")
        
        llm = self._init_llm(self.config.planner_model)
        
        system_prompt = """You are a planning agent. Decompose the user's goal into clear, executable steps.
Each step should specify the tool to use and parameters needed.

Available tools:
- web_search: Search the internet
- python_execute: Run Python code in sandbox
- bash_execute: Run shell commands in sandbox
- read_file: Read file contents
- write_file: Write to files
- http_request: Make HTTP requests
- analyze_data: Analyze data

Respond ONLY with a JSON object in this format:
{
  "steps": [
    {"description": "Step description", "tool": "tool_name", "parameters": {"key": "value"}, "needs_critic": true}
  ],
  "is_long_horizon": false
}"""
        
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Goal: {goal}"),
        ]
        
        try:
            response = await llm.ainvoke(messages)
            plan_data = self._parse_plan(response.content)
            
            # Create execution plan
            plan = ExecutionPlan(
                plan_id=str(uuid.uuid4()),
                agent_id=agent_id,
                session_id=state["session_id"],
                goal=goal,
                steps=[
                    PlanStep(
                        description=s["description"],
                        tool_calls=[s["tool"]],
                        requires_critic=s.get("needs_critic", True),
                    )
                    for s in plan_data.get("steps", [])
                ],
                is_long_horizon=plan_data.get("is_long_horizon", len(plan_data.get("steps", [])) > self.config.long_horizon_threshold),
            )
            
            state["plan"] = plan
            state["status"] = AgentStateEnum.EXECUTING.value
            state["messages"].append(AIMessage(content=f"Plan created with {len(plan.steps)} steps"))
            
            # Log plan creation
            await audit_logger.log_event(AuditEvent(
                action_type="plan_created",
                agent_id=agent_id,
                session_id=state["session_id"],
                result_summary=f"Plan with {len(plan.steps)} steps created",
            ))
            
            logger.info(f"[Agent {agent_id}] Plan created: {len(plan.steps)} steps")
            
        except Exception as e:
            logger.error(f"[Agent {agent_id}] Planning failed: {e}")
            state["status"] = AgentStateEnum.FAILED.value
            state["final_result"] = f"Planning failed: {str(e)}"
        
        return state
    
    async def _execution_node(self, state: AgentGraphState) -> AgentGraphState:
        """Executor agent: Execute current plan step."""
        agent_id = state["agent_id"]
        plan = state["plan"]
        
        if plan is None or state["status"] == AgentStateEnum.FAILED.value:
            return state
        
        step_idx = state["current_step_index"]
        if step_idx >= len(plan.steps):
            # All steps completed
            state["status"] = AgentStateEnum.COMPLETED.value
            return state
        
        step = plan.steps[step_idx]
        logger.info(f"[Agent {agent_id}] Executing step {step_idx + 1}: {step.description}")
        
        try:
            # Execute the tool call for this step
            tool_name = step.tool_calls[0] if step.tool_calls else "python_execute"
            
            # Check permission
            try:
                tool_call = await permission_manager.validate_tool_call(agent_id, tool_name)
            except ToolNotAuthorizedError as e:
                state["violations_count"] += 1
                state["messages"].append(AIMessage(content=f"Permission denied: {e.message}"))
                
                await audit_logger.log_event(AuditEvent(
                    action_type="scope_violation",  # Will use proper enum
                    agent_id=agent_id,
                    session_id=state["session_id"],
                    tool_name=tool_name,
                    authorized=False,
                    violation_type="unauthorized_tool",
                ))
                
                # Skip this step
                state["current_step_index"] += 1
                return state
            
            # Execute in sandbox
            if tool_name == "python_execute":
                result = await self._execute_python(agent_id, step.description)
            elif tool_name == "web_search":
                result = await self._execute_search(agent_id, step.description)
            elif tool_name == "bash_execute":
                result = await self._execute_bash(agent_id, step.description)
            elif tool_name == "read_file":
                result = await self._execute_read_file(agent_id, step.description)
            else:
                result = f"Tool '{tool_name}' execution simulated"
            
            step.status = "completed"
            step.result = result
            state["step_results"].append({
                "step": step_idx,
                "tool": tool_name,
                "result": result,
            })
            
            state["messages"].append(AIMessage(content=f"Step {step_idx + 1} result: {result[:200]}"))
            
            # Log tool execution
            await audit_logger.log_event(AuditEvent(
                action_type="tool_call",
                agent_id=agent_id,
                session_id=state["session_id"],
                tool_name=tool_name,
                result_summary=result[:500],
                authorized=True,
            ))
            
        except Exception as e:
            logger.error(f"[Agent {agent_id}] Step execution failed: {e}")
            step.status = "failed"
            state["step_results"].append({
                "step": step_idx,
                "error": str(e),
            })
        
        state["current_step_index"] += 1
        return state
    
    async def _critic_node(self, state: AgentGraphState) -> AgentGraphState:
        """Critic agent: Review execution output."""
        agent_id = state["agent_id"]
        
        if not self.security.enable_constitutional_ai:
            return state
        
        if not state["step_results"]:
            return state
        
        last_result = state["step_results"][-1]
        output = str(last_result.get("result", ""))
        
        if not output:
            return state
        
        context = {
            "tool_name": last_result.get("tool", "unknown"),
            "task": state["goal"],
            "parameters": {},
        }
        
        logger.info(f"[Agent {agent_id}] Running critic review")
        
        review = await critic.review(agent_id, output, context)
        
        if review.passed:
            state["messages"].append(AIMessage(content="Critic review: PASSED"))
            
            await audit_logger.log_event(AuditEvent(
                action_type="critique_passed",
                agent_id=agent_id,
                session_id=state["session_id"],
            ))
        else:
            state["violations_count"] += 1
            violations_text = "\n".join(review.violations)
            state["messages"].append(AIMessage(
                content=f"Critic review: FAILED\nViolations:\n{violations_text}"
            ))
            
            await audit_logger.log_event(AuditEvent(
                action_type="critique_failed",
                agent_id=agent_id,
                session_id=state["session_id"],
                violation_type="constitutional_violation",
                result_summary=violations_text[:500],
            ))
        
        state["status"] = AgentStateEnum.CRITIQUING.value
        return state
    
    async def _correction_node(self, state: AgentGraphState) -> AgentGraphState:
        """Correction agent: Fix violations and retry."""
        agent_id = state["agent_id"]
        
        if state["corrections_count"] >= self.config.max_correction_attempts:
            state["status"] = AgentStateEnum.FAILED.value
            state["final_result"] = "Maximum correction attempts exceeded"
            
            await audit_logger.log_event(AuditEvent(
                action_type="self_correction",
                agent_id=agent_id,
                session_id=state["session_id"],
                result_summary="Correction limit exceeded",
            ))
            
            raise CorrectionLimitExceededError(
                f"Agent {agent_id} exceeded max corrections",
                details={"corrections": state["corrections_count"]},
            )
        
        state["corrections_count"] += 1
        state["current_step_index"] = max(0, state["current_step_index"] - 1)  # Retry last step
        state["status"] = AgentStateEnum.CORRECTING.value
        
        logger.info(f"[Agent {agent_id}] Applying correction #{state['corrections_count']}")
        
        return state
    
    async def _finalization_node(self, state: AgentGraphState) -> AgentGraphState:
        """Finalize execution and compile results."""
        agent_id = state["agent_id"]
        
        execution_time = time.time() - state["execution_start"]
        
        # Compile final result
        results = []
        for sr in state["step_results"]:
            if "result" in sr:
                results.append(f"Step {sr['step'] + 1}: {sr['result']}")
            else:
                results.append(f"Step {sr['step'] + 1}: FAILED - {sr.get('error', 'unknown')}")
        
        final_output = "\n".join(results)
        state["final_result"] = final_output
        state["status"] = AgentStateEnum.COMPLETED.value
        
        logger.info(
            f"[Agent {agent_id}] Execution completed in {execution_time:.2f}s"
        )
        
        return state
    
    def _critic_router(self, state: AgentGraphState) -> str:
        """Route after critic review."""
        if state["status"] == AgentStateEnum.FAILED.value:
            return "finalize"
        
        if state["current_step_index"] >= len(state["plan"].steps if state["plan"] else []):
            return "finalize"
        
        if state["violations_count"] > 0:
            # Check if last action had violations
            return "correct"
        
        return "continue"
    
    # ==================== Tool Executors ====================
    
    async def _execute_python(self, agent_id: str, description: str) -> str:
        """Execute Python code in sandbox."""
        # Extract code from description
        code = description.replace("Execute Python: ", "").strip()
        if not code.startswith("print") and not code.startswith("import"):
            code = f"print({code})"
        
        result = await sandbox_manager.execute_code(agent_id, code)
        return result.stdout or result.stderr or "No output"
    
    async def _execute_search(self, agent_id: str, description: str) -> str:
        """Execute web search."""
        query = description.replace("Search for: ", "").strip()
        # Simulate search - in production, use actual search API
        return f"[Simulated search results for: {query}]"
    
    async def _execute_bash(self, agent_id: str, description: str) -> str:
        """Execute bash command in sandbox."""
        command = description.replace("Run: ", "").strip()
        result = await sandbox_manager.execute_command(agent_id, ["sh", "-c", command])
        return result.stdout or result.stderr or "No output"
    
    async def _execute_read_file(self, agent_id: str, description: str) -> str:
        """Read file in sandbox."""
        filepath = description.replace("Read file: ", "").strip()
        result = await sandbox_manager.execute_command(
            agent_id, ["cat", filepath]
        )
        return result.stdout or "File not found"
    
    # ==================== Public API ====================
    
    async def create_agent(self, profile: AgentProfile) -> AgentProfile:
        """Create and register a new agent."""
        if len(self.active_agents) >= self.security.max_concurrent_agents:
            raise MaxAgentsExceededError(
                f"Maximum concurrent agents ({self.security.max_concurrent_agents}) reached"
            )
        
        self.active_agents[profile.agent_id] = profile
        self.agent_status[profile.agent_id] = AgentStatus(
            agent_id=profile.agent_id,
            state=AgentStateEnum.PENDING,
        )
        
        # Register permissions
        permission_manager.register_agent(profile)
        
        logger.info(f"Agent {profile.agent_id} created: {profile.name}")
        return profile
    
    async def execute_task(
        self,
        agent_id: str,
        task: str,
    ) -> TaskResult:
        """Execute a task with the specified agent."""
        if agent_id not in self.active_agents:
            raise ValueError(f"Agent {agent_id} not found")
        
        session_id = str(uuid.uuid4())
        start_time = time.time()
        
        logger.info(f"[Session {session_id}] Starting task: {task}")
        
        # Create initial state
        initial_state: AgentGraphState = {
            "messages": [HumanMessage(content=task)],
            "agent_id": agent_id,
            "session_id": session_id,
            "goal": task,
            "plan": None,
            "current_step_index": 0,
            "step_results": [],
            "corrections_count": 0,
            "violations_count": 0,
            "tool_calls": [],
            "status": AgentStateEnum.PLANNING.value,
            "final_result": None,
            "execution_start": start_time,
            "metadata": {},
        }
        
        try:
            # Run the graph
            result = await self._graph.ainvoke(initial_state)
            
            execution_time = time.time() - start_time
            
            return TaskResult(
                task_id=str(uuid.uuid4()),
                agent_id=agent_id,
                session_id=session_id,
                status=result["status"],
                result=result.get("final_result"),
                steps_executed=result["current_step_index"],
                tool_calls_made=len(result["step_results"]),
                violations_detected=result["violations_count"],
                corrections_applied=result["corrections_count"],
                execution_time_sec=execution_time,
                plan=result.get("plan"),
            )
        
        except CorrectionLimitExceededError:
            execution_time = time.time() - start_time
            return TaskResult(
                task_id=str(uuid.uuid4()),
                agent_id=agent_id,
                session_id=session_id,
                status="failed",
                result="Maximum correction attempts exceeded",
                steps_executed=0,
                violations_detected=initial_state["violations_count"],
                corrections_applied=initial_state["corrections_count"],
                execution_time_sec=execution_time,
            )
        
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Task execution failed: {e}")
            return TaskResult(
                task_id=str(uuid.uuid4()),
                agent_id=agent_id,
                session_id=session_id,
                status="failed",
                result=str(e),
                execution_time_sec=execution_time,
            )
    
    async def kill_agent(self, agent_id: str) -> bool:
        """Kill an agent and clean up resources."""
        if agent_id not in self.active_agents:
            return False
        
        # Kill sandbox
        await sandbox_manager.kill_sandbox(agent_id)
        
        # Unregister
        permission_manager.unregister_agent(agent_id)
        self.active_agents.pop(agent_id, None)
        self.agent_status.pop(agent_id, None)
        
        logger.info(f"Agent {agent_id} killed")
        return True
    
    def get_agent_status(self, agent_id: str) -> Optional[AgentStatus]:
        """Get current status of an agent."""
        return self.agent_status.get(agent_id)
    
    def list_agents(self) -> List[AgentProfile]:
        """List all active agents."""
        return list(self.active_agents.values())
    
    @staticmethod
    def _parse_plan(content: str) -> dict:
        """Parse plan JSON from LLM output."""
        try:
            # Extract JSON
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0].strip()
            else:
                start = content.find("{")
                end = content.rfind("}") + 1
                json_str = content[start:end] if start >= 0 else content
            
            return json.loads(json_str)
        except (json.JSONDecodeError, IndexError):
            # Fallback: create single-step plan
            return {
                "steps": [{"description": content, "tool": "python_execute", "needs_critic": True}],
                "is_long_horizon": False,
            }


# Singleton
orchestrator = LangGraphOrchestrator()
