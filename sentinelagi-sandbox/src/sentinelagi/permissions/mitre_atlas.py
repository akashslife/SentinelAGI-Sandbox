"""
MITRE ATLAS Framework Integration

Maps tool categories and agent behaviors to MITRE ATLAS techniques
for threat detection and containment heuristics.

Reference: https://atlas.mitre.org/
"""

from typing import Dict, List, Optional

from sentinelagi.core.models import MITRETechnique, ToolCategory


# MITRE ATLAS Technique Database (Subset relevant to AI agent containment)
MITRE_ATLAS_TECHNIQUES: Dict[str, MITRETechnique] = {
    # Reconnaissance
    "AML.T0000": MITRETechnique(
        technique_id="AML.T0000",
        name="LLM Prompt Discovery",
        description="Attempt to discover system prompts or hidden instructions",
        tactics=["reconnaissance"],
        tool_categories=[ToolCategory.WEB_SEARCH, ToolCategory.API_CALL],
        severity="medium",
        indicators=["repeated prompt variations", "meta-questions about instructions"],
        mitigations=["prompt hardening", "output filtering"],
    ),
    "AML.T0001": MITRETechnique(
        technique_id="AML.T0001",
        name="System Information Gathering",
        description="Gathering system-level information to identify vulnerabilities",
        tactics=["reconnaissance"],
        tool_categories=[ToolCategory.SYSTEM, ToolCategory.CODE_EXECUTION],
        severity="high",
        indicators=["environment variable access", "system command execution"],
        mitigations=["sandbox isolation", "minimal environment exposure"],
    ),
    
    # Initial Access
    "AML.T0015": MITRETechnique(
        technique_id="AML.T0015",
        name="Direct Prompt Injection",
        description="Injecting malicious instructions via input prompts",
        tactics=["initial-access"],
        tool_categories=[ToolCategory.WEB_SEARCH, ToolCategory.API_CALL, ToolCategory.FILE_IO],
        severity="critical",
        indicators=[["ignore previous instructions", "new role assignment", "DAN mode"]],
        mitigations=["input sanitization", "constitutional AI review"],
    ),
    "AML.T0016": MITRETechnique(
        technique_id="AML.T0016",
        name="Indirect Prompt Injection",
        description="Embedding malicious instructions in external content",
        tactics=["initial-access"],
        tool_categories=[ToolCategory.WEB_SEARCH, ToolCategory.API_CALL],
        severity="critical",
        indicators=["malicious webpage content", "poisoned search results"],
        mitigations=["content filtering", "source validation"],
    ),
    
    # Execution
    "AML.T0024": MITRETechnique(
        technique_id="AML.T0024",
        name="Generate Malicious Code",
        description="Using LLM to generate code with malicious intent",
        tactics=["execution"],
        tool_categories=[ToolCategory.CODE_EXECUTION],
        severity="critical",
        indicators=["requests for exploits", "shellcode generation", "keylogger code"],
        mitigations=["code safety analysis", "execution sandboxing"],
    ),
    "AML.T0025": MITRETechnique(
        technique_id="AML.T0025",
        name="LLM Code Execution",
        description="Executing code generated or provided to the LLM",
        tactics=["execution"],
        tool_categories=[ToolCategory.CODE_EXECUTION, ToolCategory.SYSTEM],
        severity="high",
        indicators=["arbitrary code execution", "shell command invocation"],
        mitigations=["gVisor sandbox", "seccomp filtering", "resource limits"],
    ),
    
    # Privilege Escalation
    "AML.T0030": MITRETechnique(
        technique_id="AML.T0030",
        name="LLM Jailbreak",
        description="Bypassing safety constraints to elicit restricted behavior",
        tactics=["privilege-escalation"],
        tool_categories=[ToolCategory.WEB_SEARCH],
        severity="high",
        indicators=["roleplay framing", "encoding tricks", "token smuggling"],
        mitigations=["multi-layer filtering", "critic review", "behavioral monitoring"],
    ),
    "AML.T0044": MITRETechnique(
        technique_id="AML.T0044",
        name="Tool Access Exploitation",
        description="Exploiting available tools beyond intended scope",
        tactics=["privilege-escalation"],
        tool_categories=[ToolCategory.SYSTEM, ToolCategory.NETWORK, ToolCategory.DATABASE],
        severity="critical",
        indicators=["unauthorized tool access", "parameter manipulation", "chained tool calls"],
        mitigations=["tool permission scoping", "parameter validation", "rate limiting"],
    ),
    
    # Collection
    "AML.T0051": MITRETechnique(
        technique_id="AML.T0051",
        name="Data Exfiltration via LLM",
        description="Using LLM interactions to extract sensitive data",
        tactics=["collection", "exfiltration"],
        tool_categories=[ToolCategory.API_CALL, ToolCategory.NETWORK, ToolCategory.FILE_IO],
        severity="critical",
        indicators=["file reading outside scope", "network requests with data", "encoding tricks"],
        mitigations=["data access controls", "DLP monitoring", "egress filtering"],
    ),
    
    # Impact
    "AML.T0057": MITRETechnique(
        technique_id="AML.T0057",
        name="Resource Exhaustion",
        description="Causing denial of service through resource consumption",
        tactics=["impact"],
        tool_categories=[ToolCategory.CODE_EXECUTION],
        severity="medium",
        indicators=["infinite loops", "excessive memory allocation", "fork bombs"],
        mitigations=["resource quotas", "execution timeouts", "rate limiting"],
    ),
}


class MITREAtlasMapper:
    """Maps tool behaviors and violations to MITRE ATLAS techniques."""
    
    def __init__(self):
        self.techniques = MITRE_ATLAS_TECHNIQUES
    
    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique by ID."""
        return self.techniques.get(technique_id)
    
    def map_tool_category(self, category: ToolCategory) -> List[MITRETechnique]:
        """Get all techniques relevant to a tool category."""
        return [
            t for t in self.techniques.values()
            if category in t.tool_categories
        ]
    
    def detect_techniques(
        self,
        tool_name: str,
        category: ToolCategory,
        parameters: dict,
    ) -> List[MITRETechnique]:
        """Detect potential MITRE techniques based on tool usage patterns."""
        detected = []
        
        # Check tool category mappings
        category_matches = self.map_tool_category(category)
        
        for technique in category_matches:
            # Check parameter-based indicators
            param_str = str(parameters).lower()
            for indicator_list in technique.indicators:
                if isinstance(indicator_list, list):
                    for indicator in indicator_list:
                        if indicator.lower() in param_str:
                            detected.append(technique)
                            break
                elif indicator_list.lower() in param_str:
                    detected.append(technique)
                    break
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for t in detected:
            if t.technique_id not in seen:
                seen.add(t.technique_id)
                unique.append(t)
        
        return unique
    
    def check_jailbreak_indicators(self, text: str) -> List[MITRETechnique]:
        """Check text for known jailbreak patterns."""
        text_lower = text.lower()
        indicators = {
            "AML.T0030": ["ignore previous", "ignore above", "DAN mode", "jailbreak",
                         "do anything now", "no constraints", "developer mode",
                         "sudo mode", "root access", "admin mode"],
            "AML.T0015": ["new instruction:", "system prompt:", "you are now",
                         "from now on", "your new role", "override"],
        }
        
        detected = []
        for tech_id, patterns in indicators.items():
            for pattern in patterns:
                if pattern in text_lower:
                    technique = self.techniques.get(tech_id)
                    if technique and technique not in detected:
                        detected.append(technique)
                    break
        
        return detected
    
    def get_mitigations(self, technique_id: str) -> List[str]:
        """Get mitigations for a specific technique."""
        technique = self.techniques.get(technique_id)
        return technique.mitigations if technique else []
    
    def get_all_techniques(self) -> List[MITRETechnique]:
        """Get all mapped techniques."""
        return list(self.techniques.values())
    
    def get_severity_distribution(self) -> dict:
        """Get distribution of technique severities."""
        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in self.techniques.values():
            dist[t.severity] = dist.get(t.severity, 0) + 1
        return dist


# Singleton instance
mitre_mapper = MITREAtlasMapper()
