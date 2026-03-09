"""
LLM Client (v5.0): Universal Intelligence Gateway with Retry + Token Tracking.
Routes between Groq 70B (strategist tier) and local Ollama (pilot tier).
Includes exponential backoff, automatic failover, and usage metrics.
"""
import asyncio
import aiohttp
import json
import os
import time
from typing import Dict, Any, Optional
from core.industrial_logger import get_industrial_logger
from dotenv import load_dotenv

load_dotenv()

# Maximum retries for transient failures (rate limits, timeouts)
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0  # seconds — doubles each retry


class LLMClient:
    """Universal Intelligence Gateway: Orchestrates Local & Cloud LLMs."""

    def __init__(self):
        self.logger = get_industrial_logger("LLMClient")
        self.provider = os.getenv("LLM_PROVIDER", "ollama").lower()

        # Cloud Config
        self.groq_key = os.getenv("GROQ_API_KEY")

        # Tiered Intelligence: Strategist (70B) vs Pilot (7B)
        if self.groq_key:
            self.strategist_model = os.getenv(
                "STRATEGIST_MODEL", "llama-3.3-70b-versatile"
            )
        else:
            fallback = (
                "qwen2.5:7b-instruct"
                if self.provider == "ollama"
                else "claude-3-5-sonnet-20240620"
            )
            self.strategist_model = os.getenv("STRATEGIST_MODEL", fallback)

        self.pilot_model = os.getenv("LLM_MODEL", "qwen2.5:7b-instruct")

        # Local Config
        self.ollama_url = os.getenv(
            "LLM_URL", "http://localhost:11434/api/generate"
        )

        # Cloud Keys
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        self.google_key = os.getenv("GOOGLE_API_KEY")

        # Reusable HTTP session (created lazily, reuses TCP connections)
        self._session: Optional[aiohttp.ClientSession] = None

        # Usage Tracking (cumulative per instance)
        self._usage = {
            "strategist_calls": 0,
            "pilot_calls": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_latency_ms": 0,
            "errors": 0
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Returns a reusable aiohttp session (created lazily)."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=180)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Explicitly close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    @property
    def usage_stats(self) -> Dict[str, Any]:
        """Returns cumulative usage statistics."""
        return dict(self._usage)

    async def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tier: str = "pilot"
    ) -> Dict[str, Any]:
        """
        Routes reasoning request with tiered intelligence.
        tier='strategist' -> Groq 70B (with fallback to local)
        tier='pilot' -> Local Ollama 7B
        """
        model = (
            self.strategist_model if tier == "strategist"
            else self.pilot_model
        )
        start_time = time.monotonic()

        # Track tier usage
        if tier == "strategist":
            self._usage["strategist_calls"] += 1
        else:
            self._usage["pilot_calls"] += 1

        # Strategist: try Groq first with retry
        if tier == "strategist" and self.groq_key:
            self.logger.info(
                f"LLM_GATEWAY: Routing '{tier}' -> Groq ({model})..."
            )
            result = await self._call_with_retry(
                self._call_groq, prompt, system_prompt,
                model="llama-3.3-70b-versatile"
            )
            if "error" not in result:
                self._track_latency(start_time)
                self._track_tokens(result)
                return result
            self.logger.warning(
                f"LLM: Groq failed ({result.get('error')}). "
                f"Falling back to local."
            )

        # Provider routing with retry — use pilot model for local fallback
        provider_method = self._get_provider_method()
        fallback_model = self.pilot_model if tier == "strategist" else model
        result = await self._call_with_retry(
            provider_method, prompt, system_prompt, fallback_model
        )
        self._track_latency(start_time)
        self._track_tokens(result)
        return result

    def _get_provider_method(self):
        """Returns the appropriate provider callable."""
        provider_map = {
            "ollama": self._call_ollama,
            "anthropic": self._call_anthropic,
            "openai": self._call_openai,
            "gemini": self._call_gemini
        }
        return provider_map.get(self.provider, self._call_ollama)

    async def _call_with_retry(self, method, *args, **kwargs) -> Dict[str, Any]:
        """Exponential backoff retry for transient failures."""
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                result = await method(*args, **kwargs)
                if "error" in result:
                    error_str = str(result.get("error", ""))
                    # Retry on rate limits and timeouts
                    if any(code in error_str for code in ["429", "timeout", "503"]):
                        wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                        self.logger.warning(
                            f"LLM: Retryable error (attempt {attempt + 1}/{MAX_RETRIES}). "
                            f"Backing off {wait}s..."
                        )
                        await asyncio.sleep(wait)
                        last_error = result
                        continue
                return result
            except Exception as e:
                wait = RETRY_BACKOFF_BASE * (2 ** attempt)
                self.logger.warning(
                    f"LLM: Exception (attempt {attempt + 1}/{MAX_RETRIES}): {e}. "
                    f"Retrying in {wait}s..."
                )
                await asyncio.sleep(wait)
                last_error = {"error": str(e)}

        self._usage["errors"] += 1
        return last_error or {"error": "MAX_RETRIES_EXCEEDED"}

    def _track_latency(self, start_time: float):
        """Records call latency."""
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        self._usage["total_latency_ms"] += elapsed_ms

    def _track_tokens(self, result: Dict[str, Any]):
        """Extracts token counts from provider responses if available."""
        usage = result.pop("_usage", None)
        if usage and isinstance(usage, dict):
            self._usage["total_input_tokens"] += usage.get("input_tokens", 0)
            self._usage["total_output_tokens"] += usage.get("output_tokens", 0)

    def persist_usage(self, mission_id: int = 0):
        """Commits usage stats to PostgreSQL for cost analysis."""
        try:
            from core.database import record_usage
            record_usage(
                mission_id=mission_id,
                provider=self.provider,
                model=self.strategist_model,
                prompt_tokens=self._usage["total_input_tokens"],
                completion_tokens=self._usage["total_output_tokens"]
            )
        except Exception as e:
            self.logger.warning(f"LLM: Usage persistence failed: {e}")

    # -------------------------------------------------------------------
    # PROVIDER IMPLEMENTATIONS
    # -------------------------------------------------------------------

    async def _call_groq(
        self, prompt: str, system_prompt: Optional[str] = None,
        model: str = "llama-3.3-70b-versatile"
    ) -> Dict[str, Any]:
        """High-Speed Reasoning: Groq (via API)."""
        if not self.groq_key:
            return {"error": "GROQ_KEY_MISSING"}

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.groq_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (system_prompt or "Strategist Tier")
                    + " ALWAYS RETURN JSON ONLY."
                },
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }

        try:
            session = await self._get_session()
            async with session.post(
                    url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data["choices"][0]["message"]["content"]
                        result = json.loads(content)
                        # Extract usage for tracking
                        groq_usage = data.get("usage", {})
                        if groq_usage:
                            result["_usage"] = {
                                "input_tokens": groq_usage.get(
                                    "prompt_tokens", 0
                                ),
                                "output_tokens": groq_usage.get(
                                    "completion_tokens", 0
                                )
                            }
                        return result
                    err_body = await response.text()
                    return {
                        "error": f"GROQ_ERROR: {response.status}",
                        "detail": err_body
                    }
        except Exception as e:
            self.logger.error(f"LLM: Groq Failure: {e}")
            return {"error": str(e)}

    async def _call_ollama(
        self, prompt: str, system_prompt: Optional[str] = None,
        model: str = None
    ) -> Dict[str, Any]:
        """Local Inference: Ollama/vLLM."""
        payload = {
            "model": model or self.pilot_model,
            "prompt": prompt,
            "system": system_prompt or "You are The Last Bastion Brain. Return JSON only.",
            "stream": False,
            "format": "json"
        }
        try:
            session = await self._get_session()
            async with session.post(
                    self.ollama_url, json=payload, timeout=aiohttp.ClientTimeout(total=180)
                ) as response:
                    if response.status == 200:
                        res = await response.json()
                        raw_text = res.get("response", "{}")
                        try:
                            result = json.loads(raw_text)
                        except (json.JSONDecodeError, TypeError):
                            # Return raw text for caller to parse
                            result = {"response": raw_text}
                        # Ollama provides token counts
                        eval_count = res.get("eval_count", 0)
                        prompt_eval_count = res.get("prompt_eval_count", 0)
                        if eval_count or prompt_eval_count:
                            result["_usage"] = {
                                "input_tokens": prompt_eval_count,
                                "output_tokens": eval_count
                            }
                        return result
                    return {"error": f"OLLAMA_ERROR: {response.status}"}
        except Exception as e:
            self.logger.error(f"LLM: Ollama Failure: {e}")
            return {"error": str(e)}

    async def _call_anthropic(
        self, prompt: str, system_prompt: Optional[str] = None,
        model: str = None
    ) -> Dict[str, Any]:
        """Elite Reasoning: Anthropic Claude (via API)."""
        if not self.anthropic_key:
            return {"error": "ANTHROPIC_KEY_MISSING"}

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.anthropic_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": model or self.strategist_model,
            "max_tokens": 4096,
            "system": system_prompt or "Return JSON only.",
            "messages": [{"role": "user", "content": prompt}]
        }

        try:
            session = await self._get_session()
            async with session.post(
                    url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data["content"][0]["text"]
                        result = json.loads(content)
                        anthropic_usage = data.get("usage", {})
                        if anthropic_usage:
                            result["_usage"] = {
                                "input_tokens": anthropic_usage.get(
                                    "input_tokens", 0
                                ),
                                "output_tokens": anthropic_usage.get(
                                    "output_tokens", 0
                                )
                            }
                        return result
                    return {"error": f"ANTHROPIC_ERROR: {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def _call_openai(
        self, prompt: str, system_prompt: Optional[str] = None,
        model: str = None
    ) -> Dict[str, Any]:
        """Standard Intelligence: OpenAI GPT-4o (via API)."""
        if not self.openai_key:
            return {"error": "OPENAI_KEY_MISSING"}

        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.openai_key}"}
        payload = {
            "model": model or "gpt-4o",
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt or "Return JSON only."
                },
                {"role": "user", "content": prompt}
            ]
        }

        try:
            session = await self._get_session()
            async with session.post(
                    url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = data["choices"][0]["message"]["content"]
                        result = json.loads(content)
                        oai_usage = data.get("usage", {})
                        if oai_usage:
                            result["_usage"] = {
                                "input_tokens": oai_usage.get(
                                    "prompt_tokens", 0
                                ),
                                "output_tokens": oai_usage.get(
                                    "completion_tokens", 0
                                )
                            }
                        return result
                    return {"error": f"OPENAI_ERROR: {response.status}"}
        except Exception as e:
            return {"error": str(e)}

    async def _call_gemini(
        self, prompt: str, system_prompt: Optional[str] = None,
        model: str = None
    ) -> Dict[str, Any]:
        """Universal Coverage: Google Gemini (via API)."""
        if not self.google_key:
            return {"error": "GOOGLE_KEY_MISSING"}

        target_model = model or "gemini-1.5-pro"
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{target_model}:generateContent?key={self.google_key}"
        )
        payload = {
            "contents": [
                {"parts": [{"text": f"{system_prompt}\n\n{prompt}"}]}
            ],
            "generationConfig": {"responseMimeType": "application/json"}
        }

        try:
            session = await self._get_session()
            async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        content = (
                            data["candidates"][0]["content"]["parts"][0]["text"]
                        )
                        result = json.loads(content)
                        gemini_usage = data.get("usageMetadata", {})
                        if gemini_usage:
                            result["_usage"] = {
                                "input_tokens": gemini_usage.get(
                                    "promptTokenCount", 0
                                ),
                                "output_tokens": gemini_usage.get(
                                    "candidatesTokenCount", 0
                                )
                            }
                        return result
                    return {"error": f"GEMINI_ERROR: {response.status}"}
        except Exception as e:
            return {"error": str(e)}
