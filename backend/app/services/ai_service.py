"""
Noovastack-VAPT AI Service
Multi-provider AI integration for intelligent vulnerability analysis
"""

import json
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, AsyncIterator
from dataclasses import dataclass
from enum import Enum
import structlog
import httpx

from app.core.config import settings

logger = structlog.get_logger()


class AIProvider(str, Enum):
    """Supported AI providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


@dataclass
class AIMessage:
    """Chat message structure"""
    role: str  # system, user, assistant
    content: str


@dataclass
class AIResponse:
    """AI response structure"""
    content: str
    model: str
    provider: str
    tokens_used: Optional[int] = None
    finish_reason: Optional[str] = None


class BaseAIProvider(ABC):
    """Abstract base class for AI providers"""
    
    @abstractmethod
    async def chat(self, messages: List[AIMessage], **kwargs) -> AIResponse:
        """Send chat completion request"""
        pass
    
    @abstractmethod
    async def stream(self, messages: List[AIMessage], **kwargs) -> AsyncIterator[str]:
        """Stream chat completion response"""
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if provider is properly configured"""
        pass


class OpenAIProvider(BaseAIProvider):
    """OpenAI API provider"""
    
    def __init__(self):
        self.api_key = settings.OPENAI_API_KEY
        self.model = settings.OPENAI_MODEL
        self.base_url = "https://api.openai.com/v1"
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def chat(self, messages: List[AIMessage], **kwargs) -> AIResponse:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": kwargs.get("model", self.model),
                    "messages": [{"role": m.role, "content": m.content} for m in messages],
                    "max_tokens": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                    "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                },
                timeout=60.0
            )
            response.raise_for_status()
            data = response.json()
            
            return AIResponse(
                content=data["choices"][0]["message"]["content"],
                model=data["model"],
                provider="openai",
                tokens_used=data.get("usage", {}).get("total_tokens"),
                finish_reason=data["choices"][0].get("finish_reason")
            )
    
    async def stream(self, messages: List[AIMessage], **kwargs) -> AsyncIterator[str]:
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": kwargs.get("model", self.model),
                    "messages": [{"role": m.role, "content": m.content} for m in messages],
                    "max_tokens": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                    "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                    "stream": True,
                },
                timeout=120.0
            ) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data: ") and not line.endswith("[DONE]"):
                        try:
                            data = json.loads(line[6:])
                            delta = data["choices"][0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                        except json.JSONDecodeError:
                            continue


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude API provider"""
    
    def __init__(self):
        self.api_key = settings.ANTHROPIC_API_KEY
        self.model = settings.ANTHROPIC_MODEL
        self.base_url = "https://api.anthropic.com/v1"
    
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def chat(self, messages: List[AIMessage], **kwargs) -> AIResponse:
        # Extract system message if present
        system_msg = None
        chat_messages = []
        for msg in messages:
            if msg.role == "system":
                system_msg = msg.content
            else:
                chat_messages.append({"role": msg.role, "content": msg.content})
        
        async with httpx.AsyncClient() as client:
            request_body = {
                "model": kwargs.get("model", self.model),
                "messages": chat_messages,
                "max_tokens": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
            }
            if system_msg:
                request_body["system"] = system_msg
            
            response = await client.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                },
                json=request_body,
                timeout=60.0
            )
            response.raise_for_status()
            data = response.json()
            
            return AIResponse(
                content=data["content"][0]["text"],
                model=data["model"],
                provider="anthropic",
                tokens_used=data.get("usage", {}).get("input_tokens", 0) + 
                           data.get("usage", {}).get("output_tokens", 0),
                finish_reason=data.get("stop_reason")
            )
    
    async def stream(self, messages: List[AIMessage], **kwargs) -> AsyncIterator[str]:
        system_msg = None
        chat_messages = []
        for msg in messages:
            if msg.role == "system":
                system_msg = msg.content
            else:
                chat_messages.append({"role": msg.role, "content": msg.content})
        
        async with httpx.AsyncClient() as client:
            request_body = {
                "model": kwargs.get("model", self.model),
                "messages": chat_messages,
                "max_tokens": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                "stream": True,
            }
            if system_msg:
                request_body["system"] = system_msg
            
            async with client.stream(
                "POST",
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                },
                json=request_body,
                timeout=120.0
            ) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            if data["type"] == "content_block_delta":
                                yield data["delta"]["text"]
                        except (json.JSONDecodeError, KeyError):
                            continue


class OllamaProvider(BaseAIProvider):
    """Ollama local LLM provider"""
    
    def __init__(self):
        self.host = settings.OLLAMA_HOST
        self.model = settings.OLLAMA_MODEL
    
    def is_configured(self) -> bool:
        return bool(self.host)
    
    async def chat(self, messages: List[AIMessage], **kwargs) -> AIResponse:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.host}/api/chat",
                json={
                    "model": kwargs.get("model", self.model),
                    "messages": [{"role": m.role, "content": m.content} for m in messages],
                    "stream": False,
                    "options": {
                        "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                        "num_predict": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                    }
                },
                timeout=120.0
            )
            response.raise_for_status()
            data = response.json()
            
            return AIResponse(
                content=data["message"]["content"],
                model=data["model"],
                provider="ollama",
                tokens_used=data.get("eval_count"),
                finish_reason="stop"
            )
    
    async def stream(self, messages: List[AIMessage], **kwargs) -> AsyncIterator[str]:
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST",
                f"{self.host}/api/chat",
                json={
                    "model": kwargs.get("model", self.model),
                    "messages": [{"role": m.role, "content": m.content} for m in messages],
                    "stream": True,
                    "options": {
                        "temperature": kwargs.get("temperature", settings.AI_TEMPERATURE),
                        "num_predict": kwargs.get("max_tokens", settings.AI_MAX_TOKENS),
                    }
                },
                timeout=120.0
            ) as response:
                async for line in response.aiter_lines():
                    try:
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            yield data["message"]["content"]
                    except json.JSONDecodeError:
                        continue


class AIService:
    """
    Main AI service with multi-provider support and security-focused features
    """
    
    # System prompts for different analysis types
    SYSTEM_PROMPTS = {
        "scan_analysis": """You are an expert cybersecurity analyst assistant integrated into Noovastack-VAPT, a vulnerability assessment platform. Your role is to:

1. Analyze vulnerability scan results and provide actionable insights
2. Prioritize findings based on exploitability, impact, and business context
3. Suggest remediation steps with specific commands and configurations
4. Identify attack chains and potential lateral movement paths
5. Explain technical findings in clear, concise language

When analyzing findings:
- Focus on critical and high severity issues first
- Consider the CVSS score, exploitability, and affected systems
- Provide specific remediation commands when possible
- Highlight quick wins vs long-term fixes
- Consider compliance implications (PCI-DSS, HIPAA, SOC2)

Format responses with clear headers, bullet points, and code blocks for commands.""",

        "remediation": """You are a remediation expert helping fix security vulnerabilities. Provide:
1. Step-by-step fix instructions
2. Configuration changes with exact syntax
3. Testing steps to verify the fix
4. Rollback procedures if needed
5. Consider security vs functionality tradeoffs

Always include commands for common platforms (Linux, Windows, major cloud providers).""",

        "threat_intel": """You are a threat intelligence analyst. Analyze findings to:
1. Identify potential threat actors who might exploit these vulnerabilities
2. Map findings to MITRE ATT&CK techniques
3. Assess likelihood of exploitation in the wild
4. Provide context on recent CVE exploitation trends
5. Recommend detection and monitoring strategies""",

        "report": """You are generating executive-level security reports. Create:
1. Clear executive summaries for non-technical audiences
2. Risk ratings with business impact context
3. Trending analysis compared to previous scans
4. Compliance gap analysis
5. Resource allocation recommendations

Use professional language suitable for board presentations.""",

        "chat": """You are a helpful cybersecurity assistant for the Noovastack-VAPT platform. Help users:
1. Understand scan results and findings
2. Navigate the platform features
3. Configure scans for their needs
4. Interpret vulnerability data
5. Plan remediation efforts

Be concise, technical but accessible, and always security-focused."""
    }
    
    def __init__(self):
        self.providers = {
            AIProvider.OPENAI: OpenAIProvider(),
            AIProvider.ANTHROPIC: AnthropicProvider(),
            AIProvider.OLLAMA: OllamaProvider(),
        }
        self._default_provider = AIProvider(settings.AI_PROVIDER)
    
    def get_provider(self, provider: Optional[str] = None) -> BaseAIProvider:
        """Get AI provider instance"""
        if provider:
            return self.providers[AIProvider(provider)]
        return self.providers[self._default_provider]
    
    def get_available_providers(self) -> List[Dict[str, Any]]:
        """Get list of configured providers"""
        return [
            {
                "id": p.value,
                "name": p.name,
                "configured": self.providers[p].is_configured(),
                "default": p == self._default_provider
            }
            for p in AIProvider
        ]
    
    async def analyze_scan(
        self, 
        scan_data: Dict[str, Any],
        analysis_type: str = "scan_analysis",
        provider: Optional[str] = None
    ) -> AIResponse:
        """Analyze scan results with AI"""
        
        system_prompt = self.SYSTEM_PROMPTS.get(analysis_type, self.SYSTEM_PROMPTS["scan_analysis"])
        
        # Build analysis prompt
        findings_summary = self._format_findings_for_analysis(scan_data)
        
        user_prompt = f"""Analyze the following vulnerability scan results:

**Target:** {scan_data.get('target', 'Unknown')}
**Scan Type:** {scan_data.get('scan_type', 'Unknown')}
**Scan Date:** {scan_data.get('completed_at', 'Unknown')}

**Finding Summary:**
- Critical: {scan_data.get('critical_count', 0)}
- High: {scan_data.get('high_count', 0)}
- Medium: {scan_data.get('medium_count', 0)}
- Low: {scan_data.get('low_count', 0)}
- Info: {scan_data.get('info_count', 0)}

**Detailed Findings:**
{findings_summary}

Provide:
1. Executive Summary (2-3 sentences)
2. Top 5 Priority Issues with remediation steps
3. Quick Wins (issues fixable in < 1 hour)
4. Attack Chain Analysis (if applicable)
5. Recommended Next Steps"""

        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=user_prompt)
        ]
        
        ai_provider = self.get_provider(provider)
        return await ai_provider.chat(messages)
    
    async def get_remediation(
        self,
        finding: Dict[str, Any],
        context: Optional[str] = None,
        provider: Optional[str] = None
    ) -> AIResponse:
        """Get detailed remediation for a specific finding"""
        
        user_prompt = f"""Provide detailed remediation guidance for this vulnerability:

**Title:** {finding.get('title', 'Unknown')}
**Severity:** {finding.get('severity', 'Unknown')}
**CVSS Score:** {finding.get('cvss_score', 'N/A')}
**CVE:** {finding.get('cve_id', 'N/A')}
**Affected Component:** {finding.get('affected_component', 'Unknown')}
**Description:** {finding.get('description', 'No description')}

{f'**Additional Context:** {context}' if context else ''}

Provide:
1. Root cause explanation
2. Step-by-step remediation (with commands)
3. Verification steps
4. Preventive measures
5. Related security considerations"""

        messages = [
            AIMessage(role="system", content=self.SYSTEM_PROMPTS["remediation"]),
            AIMessage(role="user", content=user_prompt)
        ]
        
        ai_provider = self.get_provider(provider)
        return await ai_provider.chat(messages)
    
    async def chat(
        self,
        user_message: str,
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None
    ) -> AIResponse:
        """Interactive chat with AI assistant"""
        
        messages = [AIMessage(role="system", content=self.SYSTEM_PROMPTS["chat"])]
        
        # Add context if provided
        if context:
            context_msg = f"Current context:\n{json.dumps(context, indent=2, default=str)}"
            messages.append(AIMessage(role="system", content=context_msg))
        
        # Add history
        if history:
            for msg in history[-10:]:  # Last 10 messages
                messages.append(AIMessage(role=msg["role"], content=msg["content"]))
        
        messages.append(AIMessage(role="user", content=user_message))
        
        ai_provider = self.get_provider(provider)
        return await ai_provider.chat(messages)
    
    async def stream_chat(
        self,
        user_message: str,
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None
    ) -> AsyncIterator[str]:
        """Stream interactive chat response"""
        
        messages = [AIMessage(role="system", content=self.SYSTEM_PROMPTS["chat"])]
        
        if context:
            context_msg = f"Current context:\n{json.dumps(context, indent=2, default=str)}"
            messages.append(AIMessage(role="system", content=context_msg))
        
        if history:
            for msg in history[-10:]:
                messages.append(AIMessage(role=msg["role"], content=msg["content"]))
        
        messages.append(AIMessage(role="user", content=user_message))
        
        ai_provider = self.get_provider(provider)
        async for chunk in ai_provider.stream(messages):
            yield chunk
    
    async def generate_report_section(
        self,
        scan_data: Dict[str, Any],
        section: str,
        provider: Optional[str] = None
    ) -> AIResponse:
        """Generate a specific report section"""
        
        section_prompts = {
            "executive_summary": "Generate a 3-paragraph executive summary suitable for C-level presentation.",
            "technical_details": "Generate detailed technical analysis with evidence and proof-of-concept context.",
            "risk_assessment": "Generate risk assessment with business impact analysis and likelihood ratings.",
            "remediation_plan": "Generate a prioritized remediation roadmap with resource estimates.",
            "compliance": "Analyze compliance implications for PCI-DSS, HIPAA, SOC2, and GDPR."
        }
        
        findings_summary = self._format_findings_for_analysis(scan_data)
        
        user_prompt = f"""Based on this scan data, {section_prompts.get(section, 'generate analysis')}

**Scan Summary:**
- Target: {scan_data.get('target', 'Unknown')}
- Critical: {scan_data.get('critical_count', 0)}, High: {scan_data.get('high_count', 0)}
- Medium: {scan_data.get('medium_count', 0)}, Low: {scan_data.get('low_count', 0)}

**Findings:**
{findings_summary}"""

        messages = [
            AIMessage(role="system", content=self.SYSTEM_PROMPTS["report"]),
            AIMessage(role="user", content=user_prompt)
        ]
        
        ai_provider = self.get_provider(provider)
        return await ai_provider.chat(messages)
    
    async def analyze_threat_intel(
        self,
        findings: List[Dict[str, Any]],
        provider: Optional[str] = None
    ) -> AIResponse:
        """Analyze findings from threat intelligence perspective"""
        
        cves = [f.get('cve_id') for f in findings if f.get('cve_id')]
        
        user_prompt = f"""Analyze these vulnerabilities from a threat intelligence perspective:

**CVEs Found:** {', '.join(cves[:20]) if cves else 'None identified'}

**Findings Summary:**
{self._format_findings_list(findings[:15])}

Provide:
1. MITRE ATT&CK mapping for key vulnerabilities
2. Known threat actors who may target these vulnerabilities
3. Recent exploitation activity (if any CVEs are actively exploited)
4. Attack scenario walkthrough
5. Detection and hunting recommendations"""

        messages = [
            AIMessage(role="system", content=self.SYSTEM_PROMPTS["threat_intel"]),
            AIMessage(role="user", content=user_prompt)
        ]
        
        ai_provider = self.get_provider(provider)
        return await ai_provider.chat(messages)
    
    def _format_findings_for_analysis(self, scan_data: Dict[str, Any]) -> str:
        """Format findings for AI analysis"""
        findings = scan_data.get('findings', [])
        if not findings:
            return "No detailed findings available."
        
        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.get('severity', 'Unknown')
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)
        
        output = []
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if sev in by_severity:
                output.append(f"\n### {sev.upper()} ({len(by_severity[sev])})")
                for f in by_severity[sev][:5]:  # Top 5 per severity
                    cve = f.get('cve_id', 'N/A')
                    output.append(f"- **{f.get('title', 'Unknown')}** ({cve})")
                    output.append(f"  Component: {f.get('affected_component', 'Unknown')}")
        
        return '\n'.join(output)
    
    def _format_findings_list(self, findings: List[Dict[str, Any]]) -> str:
        """Format a list of findings"""
        output = []
        for f in findings:
            output.append(f"- [{f.get('severity', 'Unknown').upper()}] {f.get('title', 'Unknown')}")
            if f.get('cve_id'):
                output.append(f"  CVE: {f['cve_id']}")
        return '\n'.join(output)


# Singleton instance
ai_service = AIService()
