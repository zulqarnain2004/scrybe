"""
llm_client.py — Thin wrapper around the Anthropic API. All LLM-backed
features (executive summary, risk assessment, action plan, README/docstring
generation, and repo chat) go through this single client so the model name,
key handling, and error behavior stay consistent.

The user supplies their own API key (via the Streamlit sidebar or the
ANTHROPIC_API_KEY env var) — CodeSage never bundles or hardcodes a key.
"""

import os
import anthropic

DEFAULT_MODEL = "claude-sonnet-4-6"


class LLMNotConfigured(Exception):
    pass


class LLMRequestError(Exception):
    """Raised when the Anthropic API call itself fails (bad key, no credit,
    rate limit, etc). Message is already human-readable for display in the UI."""
    pass


def get_client(api_key: str | None = None) -> anthropic.Anthropic:
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise LLMNotConfigured(
            "No Anthropic API key set. Add one in the sidebar or set the "
            "ANTHROPIC_API_KEY environment variable."
        )
    return anthropic.Anthropic(api_key=key)


def complete(
    prompt: str,
    api_key: str | None = None,
    system: str | None = None,
    max_tokens: int = 2000,
    model: str = DEFAULT_MODEL,
) -> str:
    client = get_client(api_key)
    kwargs = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system
    try:
        response = client.messages.create(**kwargs)
    except anthropic.AuthenticationError:
        raise LLMRequestError("Invalid Anthropic API key. Check the key in the sidebar.")
    except anthropic.PermissionDeniedError:
        raise LLMRequestError("This API key doesn't have permission to use this model.")
    except anthropic.RateLimitError:
        raise LLMRequestError("Rate limited by the Anthropic API. Wait a moment and try again.")
    except anthropic.BadRequestError as e:
        msg = str(e)
        if "credit balance" in msg.lower():
            raise LLMRequestError(
                "Your Anthropic account is out of credits. Add credits at "
                "console.anthropic.com under Plans & Billing, then try again."
            )
        raise LLMRequestError(f"Anthropic API rejected the request: {msg}")
    except anthropic.APIStatusError as e:
        raise LLMRequestError(f"Anthropic API error ({e.status_code}): {e}")
    except anthropic.APIConnectionError:
        raise LLMRequestError("Couldn't reach the Anthropic API. Check your network connection.")
    return "".join(block.text for block in response.content if block.type == "text")
