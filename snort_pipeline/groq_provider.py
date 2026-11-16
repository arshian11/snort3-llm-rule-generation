"""
Groq LLM Provider & Error Mitigation Engine for Snort 3 Pipeline.

Provides production-grade resilience and automated mitigation for all Groq API
status codes and error responses according to official Groq specifications:
- Success Codes: 200 OK (with finish_reason inspection)
- Informational Codes: 206 Partial Content
- Client Error Codes: 400 Bad Request, 401 Unauthorized, 403 Forbidden,
  404 Not Found, 413 Request Entity Too Large, 422 Unprocessable Entity,
  424 Failed Dependency, 429 Too Many Requests,
  498 Flex Tier Capacity Exceeded, 499 Request Cancelled
- Server Error Codes: 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable
- Structured Error Object Extraction: { "error": { "message", "type", "code", "param" } }
"""

import os
import re
import time
import json
import random
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional, Tuple, Set

logger = logging.getLogger("snort_pipeline.groq")

# Standard Browser-like User-Agent to prevent Cloudflare 403 WAF blocks on Python-urllib
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Snort3-LLM-Engine/2.0 (compatible; GroqClient)"

# Curated high-reliability Groq chat models pool
CURATED_FALLBACK_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "allam-2-7b",
]

# Models that natively support Groq Prompt Caching (prefix matching & 50% discount)
GROQ_CACHE_SUPPORTED_MODELS: Set[str] = {
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-safeguard-20b",
}


class GroqCacheStats:
    """
    Observability & telemetry tracker for Groq Model-Aware Prompt Caching.
    Measures cache hit rates, cached token volume, and estimated savings.
    """

    def __init__(self):
        self.total_requests: int = 0
        self.cached_requests: int = 0
        self.total_prompt_tokens: int = 0
        self.total_cached_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.last_cached_tokens: int = 0
        self.last_prompt_tokens: int = 0
        self.last_hit_rate: float = 0.0
        self.last_model: str = ""
        self.last_latency_sec: float = 0.0

    @property
    def overall_hit_rate(self) -> float:
        """Calculate overall cumulative cache hit rate as percentage."""
        if self.total_prompt_tokens <= 0:
            return 0.0
        return (self.total_cached_tokens / self.total_prompt_tokens) * 100.0

    def record_usage(self, model: str, usage: Dict[str, Any], latency_sec: float = 0.0):
        """Ingest usage metadata from Groq API response."""
        self.total_requests += 1
        prompt_tokens = int(usage.get("prompt_tokens", 0))
        completion_tokens = int(usage.get("completion_tokens", 0))
        pt_details = usage.get("prompt_tokens_details", {}) or {}
        cached_tokens = int(pt_details.get("cached_tokens", 0))

        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_cached_tokens += cached_tokens
        self.last_prompt_tokens = prompt_tokens
        self.last_cached_tokens = cached_tokens
        self.last_model = model
        self.last_latency_sec = latency_sec

        hit_rate = (cached_tokens / prompt_tokens * 100.0) if prompt_tokens > 0 else 0.0
        self.last_hit_rate = hit_rate

        is_supported = model in GROQ_CACHE_SUPPORTED_MODELS
        if cached_tokens > 0:
            self.cached_requests += 1
            logger.info(
                f"[Groq Prompt Cache HIT] Model '{model}': {cached_tokens}/{prompt_tokens} tokens served from cache "
                f"({hit_rate:.1f}% hit rate | 50% token cost discount | Latency: {latency_sec:.2f}s)."
            )
        else:
            status_desc = "Prefix cached for future requests (2h TTL)" if is_supported else "Model does not support prompt caching"
            logger.info(
                f"[Groq Prompt Cache MISS] Model '{model}': 0/{prompt_tokens} cached ({status_desc} | Latency: {latency_sec:.2f}s)."
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "cached_requests": self.cached_requests,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_cached_tokens": self.total_cached_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "overall_hit_rate_pct": round(self.overall_hit_rate, 2),
            "last_request": {
                "model": self.last_model,
                "prompt_tokens": self.last_prompt_tokens,
                "cached_tokens": self.last_cached_tokens,
                "hit_rate_pct": round(self.last_hit_rate, 2),
                "latency_sec": round(self.last_latency_sec, 3),
            },
        }

    def __str__(self) -> str:
        return (
            f"GroqCacheStats(requests={self.total_requests}, cached={self.cached_requests}, "
            f"cached_tokens={self.total_cached_tokens}/{self.total_prompt_tokens}, "
            f"overall_hit_rate={self.overall_hit_rate:.1f}%)"
        )


class GroqPromptOptimizer:
    """
    Utilities for structuring prompts according to Groq Prompt Caching specifications:
    - Place static content (instructions, schemas, guidelines, catalogues) FIRST
    - Place dynamic content (target IDs, untrusted telemetry, packet dumps) LAST
    """

    @staticmethod
    def is_cache_supported_model(model: str) -> bool:
        """Check if model supports native Groq prompt caching."""
        return model in GROQ_CACHE_SUPPORTED_MODELS

    @staticmethod
    def format_cache_optimized_prompt(
        static_instructions: str,
        output_schema_or_examples: str,
        dynamic_context: str,
        untrusted_data: Optional[Any] = None,
        data_tag: str = "untrusted_network_data"
    ) -> str:
        """
        Build an exact-prefix matching prompt structure.
        """
        parts = [static_instructions.strip(), ""]
        if output_schema_or_examples:
            parts.append("### OUTPUT FORMAT & CONSTRAINTS:")
            parts.append(output_schema_or_examples.strip())
            parts.append("")

        if dynamic_context:
            parts.append("### TARGET CONTEXT:")
            parts.append(dynamic_context.strip())
            parts.append("")

        if untrusted_data is not None:
            if isinstance(untrusted_data, str):
                raw_data = untrusted_data.strip()
            else:
                raw_data = json.dumps(untrusted_data, indent=2)
            parts.append(f"<{data_tag}>")
            parts.append(raw_data)
            parts.append(f"</{data_tag}>")

        return "\n".join(parts)


class GroqErrorDetails:
    """Structured representation of Groq API error responses."""

    def __init__(
        self,
        status_code: int,
        message: str = "",
        error_type: str = "unknown_error",
        error_code: Optional[str] = None,
        param: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        raw_body: str = "",
    ):
        self.status_code = status_code
        self.message = message or f"HTTP {status_code} Error"
        self.error_type = error_type
        self.error_code = error_code
        self.param = param
        self.headers = headers or {}
        self.raw_body = raw_body

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "message": self.message,
            "type": self.error_type,
            "code": self.error_code,
            "param": self.param,
        }

    def __str__(self) -> str:
        parts = [f"HTTP {self.status_code}"]
        if self.error_type:
            parts.append(f"Type: '{self.error_type}'")
        if self.error_code:
            parts.append(f"Code: '{self.error_code}'")
        if self.param:
            parts.append(f"Param: '{self.param}'")
        parts.append(f"Message: {self.message}")
        return " | ".join(parts)


class GroqAPIError(Exception):
    """Base exception for Groq API errors with structured diagnostic details."""

    def __init__(self, details: GroqErrorDetails):
        super().__init__(str(details))
        self.details = details
        self.status_code = details.status_code


class GroqAuthenticationError(GroqAPIError):
    """Raised on HTTP 401 - Authentication failure."""
    pass


class GroqPermissionError(GroqAPIError):
    """Raised on HTTP 403 - Permission denied or geographic/WAF restriction."""
    pass


class GroqKeyManager:
    """
    Manages a pool of Groq API keys, supporting round-robin selection,
    rate-limit / capacity tracking, per-key cooldowns, and automatic failover
    across any number of keys.
    """

    def __init__(self, api_keys: Optional[List[str]] = None):
        clean_keys: List[str] = []
        if api_keys:
            for k in api_keys:
                if isinstance(k, str):
                    for sub_k in k.split(","):
                        cleaned = sub_k.strip().strip("'\"")
                        if cleaned and cleaned not in clean_keys:
                            clean_keys.append(cleaned)
        self.api_keys: List[str] = clean_keys
        self._current_idx: int = 0
        self._cooldowns: Dict[str, float] = {}   # key -> timestamp until cooldown expires
        self._disabled_keys: Set[str] = set()     # permanently disabled keys (e.g. 401)

    @classmethod
    def from_env(cls) -> "GroqKeyManager":
        """Factory creating a GroqKeyManager from system/dotenv settings."""
        try:
            from snort_pipeline.config import GROQ_API_KEYS
            return cls(GROQ_API_KEYS)
        except ImportError:
            raw = os.getenv("GROQ_API_KEYS") or os.getenv("GROQ_API_KEY", "")
            return cls(raw.split(",") if raw else [])

    def key_count(self) -> int:
        """Total number of non-disabled keys available to this manager."""
        return len([k for k in self.api_keys if k not in self._disabled_keys])

    def total_configured(self) -> int:
        """Total number of keys initially configured."""
        return len(self.api_keys)

    def mask_key(self, key: Optional[str]) -> str:
        """Return a masked representation of the key for safe logging (e.g., 'gsk_...DrJjaa')."""
        if not key:
            return "<none>"
        if len(key) <= 8:
            return "***"
        prefix = key[:4]
        suffix = key[-6:]
        return f"{prefix}...{suffix}"

    def get_active_key(self) -> Optional[str]:
        """
        Returns the currently active API key.
        If current key is disabled or on cooldown, scans forward to find an available key.
        If all valid keys are on cooldown, returns the one with earliest cooldown expiration.
        """
        valid_keys = [k for k in self.api_keys if k not in self._disabled_keys]
        if not valid_keys:
            return None

        now = time.time()
        # First check if the key at current index is usable
        curr_key = valid_keys[self._current_idx % len(valid_keys)]
        if self._cooldowns.get(curr_key, 0) <= now:
            return curr_key

        # Otherwise, search forward for any key not on cooldown
        for offset in range(len(valid_keys)):
            idx = (self._current_idx + offset) % len(valid_keys)
            k = valid_keys[idx]
            if self._cooldowns.get(k, 0) <= now:
                self._current_idx = idx
                return k

        # All keys currently on active cooldown; pick the one with earliest expiration
        earliest_key = min(valid_keys, key=lambda k: self._cooldowns.get(k, 0))
        self._current_idx = valid_keys.index(earliest_key)
        return earliest_key

    def has_alternate_key(self, current_key: Optional[str] = None) -> bool:
        """
        Returns True if there is at least one other non-disabled key
        currently available (not on cooldown).
        """
        now = time.time()
        for k in self.api_keys:
            if k != current_key and k not in self._disabled_keys:
                if self._cooldowns.get(k, 0) <= now:
                    return True
        return False

    def rotate_on_rate_limit(self, current_key: str, cooldown_seconds: float = 60.0) -> Optional[str]:
        """
        Puts current_key on cooldown and advances to the next available key.
        Returns the new active key, or None if no keys remain available without cooldown.
        """
        now = time.time()
        self._cooldowns[current_key] = now + cooldown_seconds
        logger.warning(
            f"[GroqKeyManager] Key {self.mask_key(current_key)} put on cooldown for {cooldown_seconds:.1f}s "
            f"(Rate limit / capacity reached)."
        )

        valid_keys = [k for k in self.api_keys if k not in self._disabled_keys]
        if not valid_keys:
            return None

        start_idx = self._current_idx
        for offset in range(1, len(valid_keys) + 1):
            idx = (start_idx + offset) % len(valid_keys)
            candidate = valid_keys[idx]
            if candidate != current_key and self._cooldowns.get(candidate, 0) <= now:
                self._current_idx = idx
                logger.info(
                    f"[GroqKeyManager] Rotated active key: {self.mask_key(current_key)} -> {self.mask_key(candidate)}"
                )
                return candidate

        return None

    def mark_disabled(self, key: str, reason: str = "authentication_failed"):
        """Mark a key permanently disabled for this process."""
        self._disabled_keys.add(key)
        logger.error(
            f"[GroqKeyManager] Key {self.mask_key(key)} permanently disabled: {reason}."
        )
        valid_keys = [k for k in self.api_keys if k not in self._disabled_keys]
        if valid_keys:
            self._current_idx = self._current_idx % len(valid_keys)


class GroqModelRegistry:
    """
    Dynamic model registry with capability discovery, health tracking,
    cooldown management, and intelligent model rotation.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.groq.com/openai/v1",
        key_manager: Optional[GroqKeyManager] = None,
    ):
        if key_manager is not None:
            self.key_manager = key_manager
        elif api_key:
            self.key_manager = GroqKeyManager([api_key])
        else:
            self.key_manager = GroqKeyManager([])
        self.base_url = base_url.rstrip("/")
        self._discovered_models: List[str] = []
        self._last_discovery_time: float = 0.0
        self._discovery_ttl: float = 600.0  # 10 minutes cache
        self._cooldowns: Dict[str, float] = {}  # model -> cooldown until timestamp
        self._decommissioned_or_missing: Set[str] = set()

    @property
    def api_key(self) -> str:
        return self.key_manager.get_active_key() or ""

    def discover_active_models(self) -> List[str]:
        """Fetch active chat completion models from Groq API."""
        now = time.time()
        if self._discovered_models and (now - self._last_discovery_time < self._discovery_ttl):
            return self._discovered_models

        active_key = self.key_manager.get_active_key()
        if not active_key:
            return CURATED_FALLBACK_MODELS

        url = f"{self.base_url}/models"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {active_key}",
                "User-Agent": DEFAULT_USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = []
                for item in data.get("data", []):
                    mid = item.get("id", "")
                    mods = item.get("input_modalities", ["text"])
                    # Filter for chat models, exclude audio, whisper, prompt-guards
                    if (
                        "audio" not in mods
                        and not any(x in mid.lower() for x in ["whisper", "prompt-guard", "orpheus", "safeguard"])
                        and item.get("active", True)
                    ):
                        models.append(mid)
                if models:
                    self._discovered_models = models
                    self._last_discovery_time = now
                    return models
        except Exception as e:
            logger.debug(f"[GroqRegistry] Dynamic model discovery failed: {e}. Using curated pool.")

        return CURATED_FALLBACK_MODELS

    def get_candidate_models(self, preferred_model: Optional[str] = None, prefer_caching: bool = True) -> List[str]:
        """
        Produce an ordered, deduplicated list of available candidate models,
        prioritizing prompt-caching-supported models when prefer_caching is True,
        and excluding decommissioned or rate-limited models currently in cooldown.
        """
        now = time.time()
        active = self.discover_active_models()
        candidates: List[str] = []

        # 1. Preferred model first
        if preferred_model and preferred_model not in self._decommissioned_or_missing:
            candidates.append(preferred_model)

        # 2. Add active discovered models
        for m in active:
            if m not in candidates and m not in self._decommissioned_or_missing:
                candidates.append(m)

        # 3. Add curated models as fallback
        for m in CURATED_FALLBACK_MODELS:
            if m not in candidates and m not in self._decommissioned_or_missing:
                candidates.append(m)

        # Filter out models currently on active cooldown
        available = [m for m in candidates if self._cooldowns.get(m, 0) <= now]
        res = available if available else candidates

        if prefer_caching and len(res) > 1:
            # Keep preferred model first if user specified it, otherwise prioritize cache-supported models
            first = [res[0]] if preferred_model and res[0] == preferred_model else []
            rest = [m for m in res if m not in first]
            cached_models = [m for m in rest if m in GROQ_CACHE_SUPPORTED_MODELS]
            other_models = [m for m in rest if m not in GROQ_CACHE_SUPPORTED_MODELS]
            return first + cached_models + other_models

        return res

    def mark_cooldown(self, model: str, duration_seconds: float):
        """Place a model on temporary cooldown (e.g. rate limit)."""
        self._cooldowns[model] = time.time() + duration_seconds
        logger.info(f"[GroqRegistry] Model '{model}' put on cooldown for {duration_seconds:.1f}s.")

    def mark_unavailable(self, model: str, reason: str = "decommissioned or inaccessible"):
        """Permanently mark model unavailable for the process lifetime."""
        self._decommissioned_or_missing.add(model)
        logger.warning(f"[GroqRegistry] Model '{model}' marked permanently unavailable: {reason}")


class GroqErrorParser:
    """Extracts and normalizes Groq's structured error object from HTTPError."""

    @staticmethod
    def parse(e: urllib.error.HTTPError) -> GroqErrorDetails:
        raw_body = ""
        try:
            raw_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass

        headers = dict(e.headers) if hasattr(e, "headers") and e.headers else {}
        message = ""
        error_type = "invalid_request_error"
        error_code = None
        param = None

        if raw_body:
            try:
                data = json.loads(raw_body)
                if isinstance(data, dict):
                    err = data.get("error")
                    if isinstance(err, dict):
                        message = err.get("message", "")
                        error_type = err.get("type", error_type)
                        error_code = err.get("code")
                        param = err.get("param")
                    elif isinstance(err, str):
                        message = err
            except Exception:
                message = raw_body[:300]

        if not message:
            message = getattr(e, "reason", str(e)) or f"HTTP Error {e.code}"

        return GroqErrorDetails(
            status_code=e.code,
            message=message,
            error_type=error_type,
            error_code=error_code,
            param=param,
            headers=headers,
            raw_body=raw_body,
        )

    @staticmethod
    def extract_retry_delay(details: GroqErrorDetails) -> Optional[float]:
        """
        Extract recommended retry delay in seconds from:
        1. 'retry-after' HTTP header
        2. 'x-ratelimit-reset-requests' / 'x-ratelimit-reset-tokens' headers
        3. Error message regex (e.g., 'Please try again in 7m58.656s' or 'Please try again in 1.2s')
        """
        # 1. Header: retry-after
        ra = details.headers.get("retry-after") or details.headers.get("Retry-After")
        if ra:
            try:
                val = float(ra.strip())
                if val >= 0:
                    return val
            except ValueError:
                pass

        # 2. Header: rate limit reset
        reset_hdr = details.headers.get("x-ratelimit-reset-requests") or details.headers.get("x-ratelimit-reset-tokens")
        if reset_hdr:
            try:
                val = float(reset_hdr.strip())
                if val >= 0:
                    return val
            except ValueError:
                pass

        # 3. Message regex extraction (e.g. "Please try again in 7m58.656s" or "try again in 1.2s")
        msg = details.message
        m = re.search(r"try again in\s+(?:(\d+)h)?\s*(?:(\d+)m)?\s*(?:([\d\.]+)s)?", msg, re.IGNORECASE)
        if m:
            h = float(m.group(1) or 0)
            mins = float(m.group(2) or 0)
            s = float(m.group(3) or 0)
            total = h * 3600 + mins * 60 + s
            if total > 0:
                return total

        return None


class GroqClient:
    """
    Robust Groq API client with automated understanding and mitigation of
    all standard and custom Groq status codes, plus multi-key rotation
    irrespective of the number of keys.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_keys: Optional[List[str]] = None,
        default_model: str = "openai/gpt-oss-120b",
        base_url: str = "https://api.groq.com/openai/v1",
        timeout: float = 60.0,
        key_manager: Optional[GroqKeyManager] = None,
    ):
        if key_manager is not None:
            self.key_manager = key_manager
        else:
            keys_pool: List[str] = []
            if api_keys:
                keys_pool.extend(api_keys)
            if api_key:
                if "," in api_key:
                    keys_pool.extend(api_key.split(","))
                else:
                    keys_pool.append(api_key)
            if not keys_pool:
                try:
                    from snort_pipeline.config import GROQ_API_KEYS
                    keys_pool.extend(GROQ_API_KEYS)
                except ImportError:
                    raw = os.getenv("GROQ_API_KEYS") or os.getenv("GROQ_API_KEY", "")
                    if raw:
                        keys_pool.extend(raw.split(","))
            self.key_manager = GroqKeyManager(keys_pool)

        self.default_model = default_model or os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_stats = GroqCacheStats()
        self.registry = GroqModelRegistry(key_manager=self.key_manager, base_url=self.base_url)

    def is_cache_supported(self, model: Optional[str] = None) -> bool:
        """Check if model supports native prompt caching on Groq."""
        target = model or self.default_model
        return target in GROQ_CACHE_SUPPORTED_MODELS

    def get_cache_stats(self) -> Dict[str, Any]:
        """Return cumulative Groq Prompt Caching telemetry statistics."""
        return self.cache_stats.to_dict()

    @property
    def api_key(self) -> str:
        """Returns currently active API key (backward compatible)."""
        return self.key_manager.get_active_key() or ""

    @api_key.setter
    def api_key(self, value: str):
        if value:
            self.key_manager = GroqKeyManager([value])
            self.registry.key_manager = self.key_manager

    def query(
        self,
        system_prompt: str,
        user_prompt: str,
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 2500,
    ) -> str:
        """
        High-level query entry point matching the Snort 3 pipeline contract.
        Executes with full error mitigation across available models and keys.
        """
        return self.chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 2500,
        preferred_model: Optional[str] = None,
    ) -> str:
        """
        Execute chat completion with adaptive mitigation for all Groq status codes
        and dynamic key rotation.
        """
        # Pre-flight check: ensure at least one valid API key exists
        if not self.key_manager.get_active_key():
            details = GroqErrorDetails(
                status_code=401,
                message="Missing GROQ_API_KEY(S). Please configure your Groq API key(s) in .env or environment.",
                error_type="authentication_error",
                error_code="missing_api_key",
            )
            raise GroqAuthenticationError(details)

        target_model = preferred_model or self.default_model
        models_pool = self.registry.get_candidate_models(target_model)

        last_error_details: Optional[GroqErrorDetails] = None

        for model_idx, model in enumerate(models_pool):
            # Attempt execution on current model with local retries and key rotation
            try:
                result = self._execute_model_attempts(
                    model=model,
                    messages=messages,
                    json_mode=json_mode,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                if result:
                    return result
            except GroqAuthenticationError:
                # 401 Unauthorized across all keys: Do not waste quota retrying other models
                raise
            except GroqPermissionError:
                # 403 Forbidden: Do not retry other models if account/region is blocked
                raise
            except GroqAPIError as e:
                last_error_details = e.details
                # Model-level rotation triggered by mitigation engine
                continue
            except Exception as e:
                logger.warning(f"[GroqClient] Unexpected error on model '{model}': {e}. Rotating...")
                continue

        # If all models in the pool failed, raise descriptive error
        if last_error_details:
            raise GroqAPIError(last_error_details)
        raise RuntimeError("All available Groq models failed or exceeded capacity limits.")

    def _execute_model_attempts(
        self,
        model: str,
        messages: List[Dict[str, str]],
        json_mode: bool,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """
        Executes requests against a specific model, implementing status-code specific
        mitigations (prompt adjustments, backoff, parameter clamping, and multi-key rotation).
        """
        url = f"{self.base_url}/chat/completions"
        current_messages = list(messages)
        current_max_tokens = max_tokens
        current_temp = max(0.0, min(temperature, 2.0))
        use_response_format = json_mode
        current_timeout = self.timeout

        # --- Mitigation for 400 Bad Request: ensure "json" is present if json_mode ---
        if use_response_format:
            current_messages = self._ensure_json_keyword(current_messages)

        active_key = self.key_manager.get_active_key()
        if not active_key:
            details = GroqErrorDetails(
                status_code=401,
                message="No usable Groq API key available. Check GROQ_API_KEYS in .env.",
                error_type="authentication_error",
                error_code="missing_api_key",
            )
            raise GroqAuthenticationError(details)

        # Scale attempts to try all non-rate-limited keys before giving up on this model
        max_attempts = max(3, self.key_manager.key_count() + 1)
        for attempt in range(1, max_attempts + 1):
            payload: Dict[str, Any] = {
                "model": model,
                "messages": current_messages,
                "temperature": current_temp,
                "max_tokens": current_max_tokens,
            }
            if use_response_format:
                payload["response_format"] = {"type": "json_object"}

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {active_key}",
                    "Content-Type": "application/json",
                    "User-Agent": DEFAULT_USER_AGENT,
                },
            )

            start_time = time.time()
            try:
                with urllib.request.urlopen(req, timeout=current_timeout) as resp:
                    latency = time.time() - start_time
                    resp_code = resp.status if hasattr(resp, "status") else 200

                    # --- Mitigation for 206 Partial Content ---
                    raw_data = resp.read()
                    if resp_code == 206:
                        logger.info(f"[Groq 206 Partial Content] Reassembling partial stream buffer for model '{model}'.")

                    data = json.loads(raw_data.decode("utf-8"))
                    usage = data.get("usage", {})
                    if usage:
                        self.cache_stats.record_usage(model, usage, latency_sec=latency)

                    choice = data.get("choices", [{}])[0]
                    content = choice.get("message", {}).get("content", "")
                    finish_reason = choice.get("finish_reason", "stop")

                    # --- Mitigation for 200 OK with finish_reason == 'length' (Truncation) ---
                    if finish_reason == "length":
                        logger.warning(
                            f"[Groq 200 OK] Output truncated by max_tokens={current_max_tokens}. Attempting expansion."
                        )
                        if json_mode and not self._is_valid_json(content) and current_max_tokens < 6000:
                            current_max_tokens = min(current_max_tokens * 2, 8000)
                            continue  # Retry with expanded token window

                    if content:
                        return content
                    raise ValueError("Groq returned empty completion content")

            except urllib.error.HTTPError as e:
                details = GroqErrorParser.parse(e)
                logger.info(f"[Groq API] HTTP {details.status_code} received: {details}")

                # === MITIGATION ENGINE BY ERROR CODE ===

                # 1. HTTP 400 Bad Request
                if details.status_code == 400:
                    # Check 1: Missing 'json' keyword
                    if "must contain the word 'json'" in details.message:
                        logger.info("[Mitigation 400] Injecting 'json' directive into prompt and retrying.")
                        current_messages = self._ensure_json_keyword(current_messages, force_inject=True)
                        continue

                    # Check 2: Max tokens exceeds model limit
                    if details.param == "max_tokens" or "max_tokens" in details.message:
                        m = re.search(r"less than or equal to `?(\d+)`?", details.message)
                        clamped = int(m.group(1)) if m else 2048
                        logger.info(f"[Mitigation 400] Clamping max_tokens from {current_max_tokens} to {clamped}.")
                        current_max_tokens = min(current_max_tokens, clamped)
                        continue

                    # Check 3: Model decommissioned
                    if "decommissioned" in details.message or "no longer supported" in details.message:
                        self.registry.mark_unavailable(model, reason="decommissioned")
                        raise GroqAPIError(details)

                    # Check 4: Unsupported response_format
                    if "response_format" in details.message or "json_object" in details.message:
                        logger.info("[Mitigation 400] Model does not support json_object. Falling back to prompt JSON.")
                        use_response_format = False
                        continue

                    # Check 5: Context length exceeded under 400
                    if "reduce the length" in details.message or "context_window" in details.message:
                        logger.info("[Mitigation 400] Message length exceeded context window. Truncating payload.")
                        current_messages = self._truncate_messages(current_messages)
                        continue

                    # Unrecoverable 400 for this model, rotate model
                    raise GroqAPIError(details)

                # 2. HTTP 401 Unauthorized
                elif details.status_code == 401:
                    logger.error(
                        f"[Mitigation 401] Groq authentication failed for key {self.key_manager.mask_key(active_key)}: {details.message}. "
                    )
                    self.key_manager.mark_disabled(active_key, reason=details.message)
                    if self.key_manager.has_alternate_key():
                        new_key = self.key_manager.get_active_key()
                        logger.info(
                            f"[Mitigation 401] Failing over to alternate key {self.key_manager.mask_key(new_key)} for model '{model}'."
                        )
                        active_key = new_key
                        continue
                    raise GroqAuthenticationError(details)

                # 3. HTTP 403 Forbidden
                elif details.status_code == 403:
                    logger.error(f"[Mitigation 403] Groq access forbidden: {details.message}. Check permissions/WAF.")
                    raise GroqPermissionError(details)

                # 4. HTTP 404 Not Found
                elif details.status_code == 404:
                    if details.error_code == "model_not_found" or "does not exist" in details.message:
                        logger.warning(f"[Mitigation 404] Model '{model}' not found on account. Retiring model.")
                        self.registry.mark_unavailable(model, reason="model_not_found")
                    else:
                        logger.warning(f"[Mitigation 404] Endpoint not found: {details.message}")
                    raise GroqAPIError(details)

                # 5. HTTP 413 Request Entity Too Large
                elif details.status_code == 413:
                    logger.info(f"[Mitigation 413] Request body too large for model '{model}'. Truncating payload.")
                    current_messages = self._truncate_messages(current_messages, factor=0.5)
                    continue

                # 6. HTTP 422 Unprocessable Entity
                elif details.status_code == 422:
                    logger.info(f"[Mitigation 422] Semantic unprocessable entity on model '{model}'. Relaxing constraints.")
                    current_temp = 0.0
                    use_response_format = False
                    continue

                # 7. HTTP 424 Failed Dependency (Remote MCP / Upstream)
                elif details.status_code == 424:
                    logger.info(f"[Mitigation 424] Upstream/MCP dependency failed on '{model}'. Backing off.")
                    time.sleep(1.5 + random.uniform(0.1, 0.5))
                    continue

                # 8. HTTP 429 Too Many Requests (Rate Limits: TPM / RPM / TPD)
                elif details.status_code == 429:
                    delay = GroqErrorParser.extract_retry_delay(details)
                    cooldown_time = delay if (delay is not None and delay > 0) else 60.0

                    # --- MULTI-KEY ROTATION ON 429 ---
                    if self.key_manager.has_alternate_key(active_key):
                        new_key = self.key_manager.rotate_on_rate_limit(active_key, cooldown_seconds=cooldown_time)
                        if new_key:
                            logger.warning(
                                f"[Mitigation 429 Rate Limit] Key {self.key_manager.mask_key(active_key)} rate-limited. "
                                f"Rotating to alternate key {self.key_manager.mask_key(new_key)} for model '{model}'. "
                                f"Retrying immediately (Attempt {attempt}/{max_attempts})..."
                            )
                            active_key = new_key
                            continue

                    # If no alternate key available (single key or all keys currently on cooldown):
                    if delay is not None and delay <= 5.0:
                        wait_time = delay + random.uniform(0.2, 0.8)
                        logger.info(f"[Mitigation 429] Brief rate limit on '{model}'. Backing off for {wait_time:.2f}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.warning(
                            f"[Mitigation 429] Quota or high delay on '{model}' ({cooldown_time:.1f}s) and no active alternate key. Rotating model..."
                        )
                        self.registry.mark_cooldown(model, cooldown_time)
                        raise GroqAPIError(details)

                # 9. HTTP 498 Custom: Flex Tier Capacity Exceeded
                elif details.status_code == 498:
                    logger.warning(f"[Mitigation 498] Flex tier capacity exceeded for model '{model}'.")

                    # --- MULTI-KEY ROTATION ON CAPACITY LIMIT (498) ---
                    if self.key_manager.has_alternate_key(active_key):
                        new_key = self.key_manager.rotate_on_rate_limit(active_key, cooldown_seconds=30.0)
                        if new_key:
                            logger.warning(
                                f"[Mitigation 498 Capacity Limit] Capacity limit on {self.key_manager.mask_key(active_key)}. "
                                f"Rotating to alternate key {self.key_manager.mask_key(new_key)} for model '{model}'. "
                                f"Retrying immediately (Attempt {attempt}/{max_attempts})..."
                            )
                            active_key = new_key
                            continue

                    if attempt < max_attempts:
                        backoff = (2.0 ** attempt) + random.uniform(0.5, 1.5)
                        logger.info(f"[Mitigation 498] Waiting {backoff:.2f}s before retry...")
                        time.sleep(backoff)
                        continue
                    else:
                        self.registry.mark_cooldown(model, 30.0)
                        raise GroqAPIError(details)

                # 10. HTTP 499 Custom: Request Cancelled
                elif details.status_code == 499:
                    logger.warning(f"[Mitigation 499] Request cancelled or socket timeout on '{model}'.")
                    current_timeout = min(current_timeout * 1.5, 120.0)
                    time.sleep(1.0)
                    continue

                # 11. HTTP 500, 502, 503 Server Error Codes
                elif details.status_code in (500, 502, 503):
                    backoff = (1.5 * attempt) + random.uniform(0.2, 0.8)
                    logger.warning(
                        f"[Mitigation {details.status_code}] Transient server error on '{model}'. "
                        f"Retrying in {backoff:.2f}s (Attempt {attempt}/{max_attempts})..."
                    )
                    time.sleep(backoff)
                    if attempt == max_attempts:
                        raise GroqAPIError(details)
                    continue

                else:
                    # Unknown HTTP error code
                    raise GroqAPIError(details)

            except (urllib.error.URLError, TimeoutError) as e:
                # Network or client-side socket timeout (corresponds to potential 499 conditions)
                logger.warning(f"[GroqClient] Network/Timeout error on '{model}': {e}.")
                if attempt < max_attempts:
                    current_timeout = min(current_timeout * 1.5, 90.0)
                    time.sleep(1.0 + random.uniform(0.2, 0.5))
                    continue
                raise

        raise RuntimeError(f"Max attempts exceeded on model '{model}'.")

    @staticmethod
    def _ensure_json_keyword(messages: List[Dict[str, str]], force_inject: bool = False) -> List[Dict[str, str]]:
        """
        Groq requires the word 'json' in messages when response_format is json_object.
        Ensures the directive is present in the prompt to prevent 400 Bad Request.
        """
        has_json = any("json" in m.get("content", "").lower() for m in messages)
        if has_json and not force_inject:
            return messages

        updated = []
        injected = False
        directive = "\nPlease provide your response strictly as a valid JSON object."

        for m in messages:
            role = m.get("role")
            content = m.get("content", "")
            if role in ("user", "system") and not injected:
                updated.append({"role": role, "content": content + directive})
                injected = True
            else:
                updated.append(m)

        return updated

    @staticmethod
    def _truncate_messages(messages: List[Dict[str, str]], factor: float = 0.5) -> List[Dict[str, str]]:
        """
        Mitigates 413 (Entity Too Large) and context-overflow 400 by safely pruning
        untrusted network data payloads while preserving system instructions.
        """
        truncated: List[Dict[str, str]] = []
        for m in messages:
            content = m.get("content", "")
            if m.get("role") == "system":
                # Always preserve system prompt instructions intact
                truncated.append(m)
                continue

            # Check if untrusted data block exists
            if "<untrusted_network_data>" in content and "</untrusted_network_data>" in content:
                prefix, rest = content.split("<untrusted_network_data>", 1)
                data_block, suffix = rest.split("</untrusted_network_data>", 1)
                # Cut down data block size
                keep_len = max(int(len(data_block) * factor), 500)
                pruned_block = data_block[:keep_len] + "\n... [Telemetry payload truncated to prevent context overflow] ...\n"
                new_content = f"{prefix}<untrusted_network_data>{pruned_block}</untrusted_network_data>{suffix}"
                truncated.append({"role": m.get("role", "user"), "content": new_content})
            else:
                keep_len = max(int(len(content) * factor), 1000)
                new_content = content[:keep_len] + "\n... [Input prompt truncated to fit context window] ..."
                truncated.append({"role": m.get("role", "user"), "content": new_content})

        return truncated

    @staticmethod
    def _is_valid_json(text: str) -> bool:
        """Helper to verify if a response string forms complete valid JSON."""
        if not text:
            return False
        clean = text.strip()
        if clean.startswith("```"):
            m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean)
            if m:
                clean = m.group(1).strip()
        try:
            json.loads(clean)
            return True
        except Exception:
            return False
