"""Context-aware string auditor using ReAct pattern.

This module implements a two-phase audit process:
1. Initial screening: Quick LLM scan of strings
2. Context-enriched review: For uncertain strings, LLM can request code context

The LLM can use tools to:
- Get code context around a string usage
- Search for related code patterns
- Decompile specific classes for deeper analysis
"""

import json
import os
import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from log import logger


@dataclass
class StringWithContext:
    """A string with optional code context."""
    value: str
    class_name: str
    file_path: str
    line: int = 0
    context: str = ""
    usage_context: str = ""  # How the string is used in code
    related_code: str = ""   # Surrounding code from decompilation
    
    
@dataclass
class ContextRequest:
    """A request from LLM to get more context."""
    string_value: str
    request_type: str  # "decompile", "search_usage", "get_surrounding"
    reason: str


class JarContextProvider:
    """Provides code context for strings in JAR files using CFR decompiler."""
    
    def __init__(self, jar_path: str, cfr_path: Optional[str] = None):
        self.jar_path = Path(jar_path)
        self.cfr_path = cfr_path or self._find_cfr()
        self._decompiled_cache: Dict[str, str] = {}
        self._class_list: Optional[List[str]] = None
        
    def _find_cfr(self) -> Optional[str]:
        """Find CFR decompiler jar."""
        search_paths = [
            Path.home() / ".local" / "share" / "cfr" / "cfr.jar",
            Path("/usr/share/java/cfr.jar"),
            Path("/opt/cfr/cfr.jar"),
            Path.home() / "cfr.jar",
        ]
        for p in search_paths:
            if p.exists():
                return str(p)
        # Try to find any cfr*.jar
        for p in Path.home().glob("**/cfr*.jar"):
            return str(p)
        return None
    
    def has_decompiler(self) -> bool:
        """Check if decompiler is available."""
        return self.cfr_path is not None and Path(self.cfr_path).exists()
    
    def list_classes(self) -> List[str]:
        """List all classes in the JAR."""
        if self._class_list is not None:
            return self._class_list
            
        self._class_list = []
        try:
            with zipfile.ZipFile(self.jar_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.class') and not name.startswith('META-INF'):
                        class_name = name.replace('/', '.').replace('.class', '')
                        self._class_list.append(class_name)
        except Exception as e:
            logger.warning(f"Failed to list classes: {e}")
        return self._class_list
    
    def find_classes_containing_string(self, search_string: str) -> List[str]:
        """Find classes that contain a specific string in their constant pool."""
        matching_classes = []
        try:
            with zipfile.ZipFile(self.jar_path, 'r') as zf:
                for name in zf.namelist():
                    if not name.endswith('.class'):
                        continue
                    try:
                        data = zf.read(name)
                        # Simple check: look for the string in raw bytes
                        if search_string.encode('utf-8') in data:
                            class_name = name.replace('/', '.').replace('.class', '')
                            matching_classes.append(class_name)
                    except:
                        continue
        except Exception as e:
            logger.warning(f"Failed to search classes: {e}")
        return matching_classes
    
    def decompile_class(self, class_name: str) -> str:
        """Decompile a specific class using CFR."""
        if class_name in self._decompiled_cache:
            return self._decompiled_cache[class_name]
            
        if not self.has_decompiler():
            return f"[Decompiler not available. Install CFR: https://www.benf.org/other/cfr/]"
        
        # Convert class name to path format
        class_path = class_name.replace('.', '/') + '.class'
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Extract the specific class
                with zipfile.ZipFile(self.jar_path, 'r') as zf:
                    try:
                        zf.extract(class_path, tmpdir)
                    except KeyError:
                        return f"[Class not found: {class_name}]"
                
                class_file = Path(tmpdir) / class_path
                
                # Run CFR
                result = subprocess.run(
                    ["java", "-jar", self.cfr_path, str(class_file)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    decompiled = result.stdout
                    self._decompiled_cache[class_name] = decompiled
                    return decompiled
                else:
                    return f"[Decompilation failed: {result.stderr[:200]}]"
                    
        except subprocess.TimeoutExpired:
            return "[Decompilation timed out]"
        except Exception as e:
            return f"[Decompilation error: {e}]"
    
    def get_string_usage_context(self, string_value: str, class_name: str) -> str:
        """Get the code context where a string is used."""
        decompiled = self.decompile_class(class_name)
        
        if decompiled.startswith("["):
            return decompiled  # Error message
        
        # Find lines containing the string
        lines = decompiled.split('\n')
        context_lines = []
        
        for i, line in enumerate(lines):
            if string_value in line:
                # Get surrounding context (5 lines before and after)
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                context_lines.append(f"--- Found at line {i+1} ---")
                context_lines.extend(lines[start:end])
                context_lines.append("")
        
        if context_lines:
            return '\n'.join(context_lines)
        else:
            return f"[String '{string_value}' not found in decompiled code of {class_name}]"
    
    def search_pattern_in_jar(self, pattern: str, max_results: int = 10) -> List[Dict[str, str]]:
        """Search for a regex pattern across all decompiled classes."""
        results = []
        regex = re.compile(pattern, re.IGNORECASE)
        
        for class_name in self.list_classes():
            if len(results) >= max_results:
                break
                
            decompiled = self.decompile_class(class_name)
            if decompiled.startswith("["):
                continue
                
            for match in regex.finditer(decompiled):
                # Get surrounding context
                start = max(0, match.start() - 200)
                end = min(len(decompiled), match.end() + 200)
                context = decompiled[start:end]
                
                results.append({
                    "class": class_name,
                    "match": match.group(),
                    "context": context
                })
                
                if len(results) >= max_results:
                    break
        
        return results


class ReActStringAuditor:
    """ReAct-based string auditor that can request context on demand."""
    
    # Patterns that often need context to determine if they're vulnerabilities
    CONTEXT_NEEDED_PATTERNS = [
        r'^[a-zA-Z]+-reserved-',    # Reserved user patterns like viptela-reserved-uc
        r'^[a-zA-Z]+-device-',      # Device user patterns
        r'^[a-zA-Z]+-admin$',       # Admin user patterns
        r'validate|verify|auth',    # Authentication related
        r'password|secret|key',     # Credential related but might be field names
        r'\.equals\(',              # Comparison patterns
    ]
    
    def __init__(self, model, jar_path: str):
        self.model = model
        self.jar_path = jar_path
        self.context_provider = JarContextProvider(jar_path)
        self._context_requests: List[ContextRequest] = []
        
    def _needs_context_check(self, string_value: str) -> bool:
        """Check if a string likely needs code context to properly assess."""
        for pattern in self.CONTEXT_NEEDED_PATTERNS:
            if re.search(pattern, string_value, re.IGNORECASE):
                return True
        return False
    
    def _build_react_prompt(self, strings: List[Dict[str, Any]], phase: str = "initial") -> str:
        """Build prompt for ReAct-style analysis."""
        
        if phase == "initial":
            return self._build_initial_screening_prompt(strings)
        else:
            return self._build_context_analysis_prompt(strings)
    
    def _build_initial_screening_prompt(self, strings: List[Dict[str, Any]]) -> str:
        """Build prompt for initial screening phase."""
        
        string_list = []
        for idx, s in enumerate(strings, 1):
            value = s.get("value", "")
            class_name = s.get("class_name", "unknown")
            string_list.append(f"{idx}. [{class_name}] {value}")
        
        return f"""You are a security analyst reviewing hardcoded strings from a JAR file.

TASK: Analyze these strings and categorize them into three groups:

1. DEFINITELY_SUSPICIOUS: Clearly sensitive (passwords, keys, tokens with actual values)
2. NEEDS_CONTEXT: Cannot determine without seeing how it's used in code
   - Examples: usernames that might be backdoor accounts, paths that might store credentials
   - Strings that look like they could be part of authentication bypass logic
3. BENIGN: Clearly not security relevant

For NEEDS_CONTEXT items, explain what context you would need to make a determination.

IMPORTANT: Pay special attention to:
- Patterns like "xxx-reserved-xxx", "xxx-device-xxx" - these often indicate special/backdoor accounts
- Strings near authentication/validation logic
- File paths that might contain credentials

Return JSON:
{{
    "definitely_suspicious": [
        {{"value": "...", "category": "...", "reason": "...", "confidence": 0.9}}
    ],
    "needs_context": [
        {{"value": "...", "potential_risk": "...", "context_needed": "Need to see how this is used in authentication logic"}}
    ],
    "benign_count": 123
}}

Strings to analyze:
{chr(10).join(string_list)}
"""

    def _build_context_analysis_prompt(self, items_with_context: List[Dict[str, Any]]) -> str:
        """Build prompt for context-enriched analysis."""
        
        context_blocks = []
        for item in items_with_context:
            value = item.get("value", "")
            context = item.get("code_context", "")
            potential_risk = item.get("potential_risk", "")
            
            context_blocks.append(f"""
--- String: {value} ---
Potential Risk: {potential_risk}
Code Context:
```java
{context}
```
""")
        
        return f"""You are a security analyst. You previously flagged these strings as needing code context.
Now analyze them WITH their code context to determine if they are actual security issues.

Focus on:
1. Is this string used in authentication bypass logic?
2. Is this a backdoor account that bypasses normal authentication?
3. Does the code show this string enables special/privileged access?

For each string, provide your final assessment with confidence.

Return JSON:
{{
    "findings": [
        {{
            "value": "...",
            "is_vulnerability": true/false,
            "category": "backdoor_account/hardcoded_credential/...",
            "reason": "Detailed explanation of why this is/isn't a vulnerability based on code context",
            "confidence": 0.95,
            "code_evidence": "The specific code pattern that proves this"
        }}
    ]
}}

Strings with context:
{chr(10).join(context_blocks)}
"""

    async def audit_with_context(
        self, 
        strings: List[Dict[str, Any]],
        max_context_requests: int = 50
    ) -> Dict[str, Any]:
        """
        Two-phase audit with context enrichment.
        
        Phase 1: Initial screening - categorize strings
        Phase 2: For uncertain items, get code context and re-analyze
        """
        
        logger.info(f"[ReActAudit] Phase 1: Initial screening of {len(strings)} strings")
        
        # Phase 1: Initial screening
        initial_prompt = self._build_initial_screening_prompt(strings)
        initial_response = await self.model.chat(initial_prompt)
        initial_result = self._parse_json_response(initial_response)
        
        if not initial_result:
            logger.error("[ReActAudit] Failed to parse initial screening response")
            return {"error": "Failed to parse initial screening response"}
        
        definitely_suspicious = initial_result.get("definitely_suspicious", [])
        needs_context = initial_result.get("needs_context", [])
        
        logger.info(f"[ReActAudit] Phase 1 results: {len(definitely_suspicious)} suspicious, {len(needs_context)} need context")
        
        # Phase 2: Context enrichment for uncertain items
        context_enriched_findings = []
        
        if needs_context and self.context_provider.has_decompiler():
            logger.info(f"[ReActAudit] Phase 2: Getting context for {min(len(needs_context), max_context_requests)} items")
            
            items_with_context = []
            for item in needs_context[:max_context_requests]:
                value = item.get("value", "")
                
                # Find which classes contain this string
                containing_classes = self.context_provider.find_classes_containing_string(value)
                
                if containing_classes:
                    # Get context from the first matching class
                    class_name = containing_classes[0]
                    code_context = self.context_provider.get_string_usage_context(value, class_name)
                    
                    items_with_context.append({
                        "value": value,
                        "potential_risk": item.get("potential_risk", ""),
                        "class_name": class_name,
                        "code_context": code_context[:2000]  # Limit context size
                    })
            
            if items_with_context:
                # Phase 2: Analyze with context
                context_prompt = self._build_context_analysis_prompt(items_with_context)
                context_response = await self.model.chat(context_prompt)
                context_result = self._parse_json_response(context_response)
                
                if context_result and "findings" in context_result:
                    context_enriched_findings = [
                        f for f in context_result["findings"] 
                        if f.get("is_vulnerability", False)
                    ]
                    logger.info(f"[ReActAudit] Phase 2 results: {len(context_enriched_findings)} confirmed vulnerabilities")
        else:
            if not self.context_provider.has_decompiler():
                logger.warning("[ReActAudit] CFR decompiler not available, skipping Phase 2")
        
        # Combine results
        all_findings = definitely_suspicious + context_enriched_findings
        
        return {
            "phase1_suspicious": len(definitely_suspicious),
            "phase2_context_checked": len(needs_context),
            "phase2_confirmed": len(context_enriched_findings),
            "total_findings": len(all_findings),
            "findings": all_findings,
            "decompiler_available": self.context_provider.has_decompiler()
        }
    
    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from LLM response."""
        if not response:
            return None
            
        # Remove markdown code blocks
        response = response.strip()
        if response.startswith("```"):
            lines = response.split('\n')
            response = '\n'.join(lines[1:-1] if lines[-1].strip() == '```' else lines[1:])
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                try:
                    return json.loads(match.group())
                except:
                    pass
            return None


def download_cfr(target_dir: Optional[str] = None) -> str:
    """Download CFR decompiler if not present."""
    import urllib.request
    
    target_dir = Path(target_dir or Path.home() / ".local" / "share" / "cfr")
    target_dir.mkdir(parents=True, exist_ok=True)
    
    cfr_path = target_dir / "cfr.jar"
    if cfr_path.exists():
        return str(cfr_path)
    
    # Download latest CFR
    cfr_url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
    logger.info(f"Downloading CFR decompiler to {cfr_path}")
    
    urllib.request.urlretrieve(cfr_url, cfr_path)
    return str(cfr_path)
