"""
LLM Provider Abstraction Layer

Unified interface for multiple LLM providers used by the SOC Agent
for intelligent threat analysis, reasoning, and report generation.

Supported providers:
- GLM-4 (Zhipu AI): OpenAI-compatible API at open.bigmodel.cn
- OpenAI (GPT-4, etc.): api.openai.com
- Anthropic (Claude): api.anthropic.com, Messages API
- Google (Gemini): generativelanguage.googleapis.com
- DeepSeek: api.deepseek.com, OpenAI-compatible
- MiniMax: api.minimax.chat, OpenAI-compatible
- Zero-One (Yi / 01.AI): api.01.ai, OpenAI-compatible
- Groq: api.groq.com, OpenAI-compatible
- Mistral: api.mistral.ai, OpenAI-compatible

Most providers expose an OpenAI-compatible /chat/completions endpoint,
so the majority share one code path. Anthropic and Gemini have bespoke
request formats and get their own implementations.
"""

import logging
import aiohttp
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized LLM response."""
    content: str
    provider: str
    model: str
    usage: Dict[str, int]
    raw: Dict[str, Any]
    success: bool = True
    error: Optional[str] = None


class BaseLLMProvider(ABC):
    """Abstract base for all LLM providers."""

    def __init__(self, api_key: str, model: str, config: Dict[str, Any] = None):
        self.api_key = api_key
        self.model = model
        self.config = config or {}
        self.temperature = self.config.get("temperature", 0.3)
        self.max_tokens = self.config.get("max_tokens", 2048)

    @abstractmethod
    async def chat(self, messages: List[Dict[str, str]]) -> LLMResponse:
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass


class OpenAICompatibleProvider(BaseLLMProvider):
    """
    Shared implementation for all OpenAI-compatible APIs.
    Covers: OpenAI, GLM-4, DeepSeek, MiniMax, 01.AI, Groq, Mistral.
    """

    ENDPOINTS = {
        "openai":   "https://api.openai.com/v1/chat/completions",
        "glm":      "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "deepseek": "https://api.deepseek.com/chat/completions",
        "minimax":  "https://api.minimax.chat/v1/text/chatcompletion_v2",
        "01ai":     "https://api.01.ai/v1/chat/completions",
        "groq":     "https://api.groq.com/openai/v1/chat/completions",
        "mistral":  "https://api.mistral.ai/v1/chat/completions",
    }

    DEFAULT_MODELS = {
        "openai":   "gpt-4o",
        "glm":      "glm-4-plus",
        "deepseek": "deepseek-chat",
        "minimax":  "MiniMax-Text-01",
        "01ai":     "yi-large",
        "groq":     "llama-3.3-70b-versatile",
        "mistral":  "mistral-large-latest",
    }

    def __init__(self, provider_key: str, api_key: str,
                 model: str = None, config: Dict[str, Any] = None):
        self._provider_key = provider_key
        resolved_model = model or self.DEFAULT_MODELS.get(provider_key, "")
        super().__init__(api_key, resolved_model, config)
        self.endpoint = self.config.get(
            "endpoint", self.ENDPOINTS.get(provider_key, "")
        )

    @property
    def provider_name(self) -> str:
        return self._provider_key

    async def chat(self, messages: List[Dict[str, str]]) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.endpoint, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as resp:
                    body = await resp.json()

                    if resp.status != 200:
                        error_msg = body.get("error", {}).get("message", str(body))
                        return LLMResponse(
                            content="", provider=self.provider_name,
                            model=self.model, usage={}, raw=body,
                            success=False, error=f"HTTP {resp.status}: {error_msg}"
                        )

                    choice = body.get("choices", [{}])[0]
                    content = choice.get("message", {}).get("content", "")
                    usage = body.get("usage", {})

                    return LLMResponse(
                        content=content,
                        provider=self.provider_name,
                        model=body.get("model", self.model),
                        usage={
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0),
                            "total_tokens": usage.get("total_tokens", 0),
                        },
                        raw=body,
                    )

        except Exception as e:
            logger.error(f"LLM request to {self.provider_name} failed: {e}")
            return LLMResponse(
                content="", provider=self.provider_name,
                model=self.model, usage={}, raw={},
                success=False, error=str(e)
            )


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude, uses the Messages API."""

    ENDPOINT = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str = None,
                 config: Dict[str, Any] = None):
        super().__init__(api_key, model or "claude-sonnet-4-20250514", config)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def chat(self, messages: List[Dict[str, str]]) -> LLMResponse:
        system_msg = ""
        chat_messages = []
        for m in messages:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                chat_messages.append(m)

        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": chat_messages,
        }
        if system_msg:
            payload["system"] = system_msg

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.ENDPOINT, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as resp:
                    body = await resp.json()

                    if resp.status != 200:
                        error_msg = body.get("error", {}).get("message", str(body))
                        return LLMResponse(
                            content="", provider="anthropic",
                            model=self.model, usage={}, raw=body,
                            success=False, error=f"HTTP {resp.status}: {error_msg}"
                        )

                    content_blocks = body.get("content", [])
                    content = "".join(
                        b.get("text", "") for b in content_blocks
                        if b.get("type") == "text"
                    )
                    usage = body.get("usage", {})

                    return LLMResponse(
                        content=content,
                        provider="anthropic",
                        model=body.get("model", self.model),
                        usage={
                            "prompt_tokens": usage.get("input_tokens", 0),
                            "completion_tokens": usage.get("output_tokens", 0),
                            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                        },
                        raw=body,
                    )

        except Exception as e:
            logger.error(f"Anthropic request failed: {e}")
            return LLMResponse(
                content="", provider="anthropic",
                model=self.model, usage={}, raw={},
                success=False, error=str(e)
            )


class GeminiProvider(BaseLLMProvider):
    """Google Gemini, uses the generateContent REST API."""

    ENDPOINT_TEMPLATE = (
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    )

    def __init__(self, api_key: str, model: str = None,
                 config: Dict[str, Any] = None):
        super().__init__(api_key, model or "gemini-2.0-flash", config)

    @property
    def provider_name(self) -> str:
        return "gemini"

    async def chat(self, messages: List[Dict[str, str]]) -> LLMResponse:
        system_instruction = None
        contents = []
        role_map = {"user": "user", "assistant": "model"}

        for m in messages:
            if m["role"] == "system":
                system_instruction = m["content"]
            else:
                contents.append({
                    "role": role_map.get(m["role"], "user"),
                    "parts": [{"text": m["content"]}]
                })

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            }
        }
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        url = self.ENDPOINT_TEMPLATE.format(model=self.model)
        params = {"key": self.api_key}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, params=params,
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as resp:
                    body = await resp.json()

                    if resp.status != 200:
                        error_msg = body.get("error", {}).get("message", str(body))
                        return LLMResponse(
                            content="", provider="gemini",
                            model=self.model, usage={}, raw=body,
                            success=False, error=f"HTTP {resp.status}: {error_msg}"
                        )

                    candidates = body.get("candidates", [{}])
                    parts = candidates[0].get("content", {}).get("parts", [])
                    content = "".join(p.get("text", "") for p in parts)

                    usage_meta = body.get("usageMetadata", {})

                    return LLMResponse(
                        content=content,
                        provider="gemini",
                        model=self.model,
                        usage={
                            "prompt_tokens": usage_meta.get("promptTokenCount", 0),
                            "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
                            "total_tokens": usage_meta.get("totalTokenCount", 0),
                        },
                        raw=body,
                    )

        except Exception as e:
            logger.error(f"Gemini request failed: {e}")
            return LLMResponse(
                content="", provider="gemini",
                model=self.model, usage={}, raw={},
                success=False, error=str(e)
            )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY = {
    "glm":       lambda key, model, cfg: OpenAICompatibleProvider("glm", key, model, cfg),
    "openai":    lambda key, model, cfg: OpenAICompatibleProvider("openai", key, model, cfg),
    "deepseek":  lambda key, model, cfg: OpenAICompatibleProvider("deepseek", key, model, cfg),
    "minimax":   lambda key, model, cfg: OpenAICompatibleProvider("minimax", key, model, cfg),
    "01ai":      lambda key, model, cfg: OpenAICompatibleProvider("01ai", key, model, cfg),
    "groq":      lambda key, model, cfg: OpenAICompatibleProvider("groq", key, model, cfg),
    "mistral":   lambda key, model, cfg: OpenAICompatibleProvider("mistral", key, model, cfg),
    "anthropic": lambda key, model, cfg: AnthropicProvider(key, model, cfg),
    "gemini":    lambda key, model, cfg: GeminiProvider(key, model, cfg),
}


def create_llm_provider(
    provider: str,
    api_key: str,
    model: str = None,
    config: Dict[str, Any] = None
) -> BaseLLMProvider:
    """
    Factory function to create an LLM provider.

    Args:
        provider: One of glm, openai, anthropic, gemini, deepseek, minimax,
                  01ai, groq, mistral
        api_key:  API key for the provider
        model:    Model name override (uses sensible defaults otherwise)
        config:   Extra config (temperature, max_tokens, endpoint override)

    Returns:
        BaseLLMProvider instance ready to use
    """
    factory = PROVIDER_REGISTRY.get(provider.lower())
    if factory is None:
        supported = ", ".join(sorted(PROVIDER_REGISTRY.keys()))
        raise ValueError(f"Unknown LLM provider '{provider}'. Supported: {supported}")
    return factory(api_key, model, config)


# ---------------------------------------------------------------------------
# SOC Analysis Prompt
# ---------------------------------------------------------------------------

SOC_ANALYSIS_SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst AI.
You analyze security events and threat intelligence data to produce actionable assessments.

Your analysis must be structured as JSON with the following fields:
{
  "threat_assessment": "one paragraph summarizing the threat",
  "risk_modifier": <float 0.0-1.0, how much this changes the risk score>,
  "confidence": <float 0.0-1.0>,
  "key_findings": ["finding1", "finding2", ...],
  "recommended_actions": ["action1", "action2", ...],
  "ioc_analysis": {
    "malicious_indicators": ["indicator1", ...],
    "suspicious_indicators": ["indicator1", ...],
    "benign_indicators": ["indicator1", ...]
  },
  "attack_classification": "e.g. brute_force, malware_c2, phishing, ddos, insider_threat, reconnaissance, or benign",
  "mitre_tactics": ["TA0001", ...],
  "urgency": "critical | high | medium | low"
}

Be precise. Do not hallucinate threat data. Only analyze what is provided.
If threat intel data is empty or inconclusive, say so and lower confidence accordingly."""


def build_analysis_prompt(event_data: Dict[str, Any],
                          intel_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build the chat messages for SOC analysis."""
    user_content = f"""Analyze this security event and threat intelligence data.

## Security Event
```json
{json.dumps(event_data, indent=2, default=str)}
```

## Threat Intelligence Results
```json
{json.dumps(intel_data, indent=2, default=str)}
```

Provide your structured JSON analysis."""

    return [
        {"role": "system", "content": SOC_ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
