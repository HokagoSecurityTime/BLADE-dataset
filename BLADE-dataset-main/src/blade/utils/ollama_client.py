"""Ollama HTTP 호출 단일화.

A/B/C 트랙이 각자 requests.post 로 직접 호출하던 것을 한 곳에 모음.
임베딩, 텍스트 생성, 헬스체크, 모델 사전 로드를 제공.
"""

from __future__ import annotations

import re
import json as _json
from typing import Any

import requests

from blade import config


class OllamaError(RuntimeError):
    pass


# --- 헬스체크 / 모델 목록 ----------------------------------------------


def is_alive(timeout: int = 5) -> bool:
    try:
        r = requests.get(config.OLLAMA_TAGS_URL, timeout=timeout)
        r.raise_for_status()
        return True
    except Exception:
        return False


def list_models(timeout: int = 5) -> list[str]:
    r = requests.get(config.OLLAMA_TAGS_URL, timeout=timeout)
    r.raise_for_status()
    return [m["name"] for m in r.json().get("models", [])]


# --- 임베딩 ------------------------------------------------------------


def embed(text: str, model: str | None = None, timeout: int = 60) -> list[float] | None:
    """단일 텍스트 임베딩. 실패 시 None 반환 (호출 측이 skip 결정)."""
    model = model or config.EMBED_MODEL
    try:
        r = requests.post(
            config.OLLAMA_EMBED_URL,
            json={"model": model, "prompt": text},
            timeout=timeout,
        )
        r.raise_for_status()
        emb = r.json().get("embedding")
        return list(map(float, emb)) if emb else None
    except Exception as exc:
        print(f"  [warn] embed failed: {exc}")
        return None


# --- 텍스트 생성 -------------------------------------------------------


def generate(
    prompt: str,
    *,
    model: str | None = None,
    temperature: float = 0.0,
    num_predict: int = 256,
    keep_alive: str = "10m",
    timeout: int = 300,
    options: dict[str, Any] | None = None,
) -> str:
    """텍스트 생성. response 문자열 반환. 실패 시 OllamaError."""
    model = model or config.ENRICHMENT_MODEL
    payload_options = {"temperature": temperature, "num_predict": num_predict}
    if options:
        payload_options.update(options)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": keep_alive,
        "options": payload_options,
    }
    try:
        r = requests.post(config.OLLAMA_GENERATE_URL, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("response", "")
    except Exception as exc:
        raise OllamaError(f"generate failed (model={model}): {exc}") from exc


def warmup(model: str | None = None) -> bool:
    """모델 사전 로드. 첫 호출 지연 방지. 도달 가능하면 True."""
    model = model or config.ENRICHMENT_MODEL
    try:
        generate("ok", model=model, num_predict=1, timeout=300)
        return True
    except OllamaError:
        return False


# --- JSON 파싱 헬퍼 ----------------------------------------------------


def parse_first_json(text: str) -> dict[str, Any] | None:
    """LLM 응답에서 첫 번째 JSON 객체를 파싱. 펜스/평문 모두 처리."""
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else None
    if not candidate:
        m = re.search(r"\{.*\}", text, re.S)
        candidate = m.group(0) if m else None
    if not candidate:
        return None
    try:
        return _json.loads(candidate)
    except Exception:
        return None
