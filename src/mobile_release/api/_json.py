"""Finite in-memory JSON admission. No IO, execution or schema fetching."""
from __future__ import annotations

import json
import math
from typing import Any

from ..config import MAX_CONFIG_BYTES
from ..errors import ConfigurationError

MAX_DEPTH = 32
MAX_NODES = 20_000


def bounded_json_text(value: Any, *, max_bytes: int = MAX_CONFIG_BYTES,
                      max_nodes: int = MAX_NODES, max_depth: int = MAX_DEPTH) -> str:
    """Reject Python-only, cyclic/deep and oversized values before serialization."""
    pending = [(value, 0)]
    nodes = 0
    minimum_bytes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        kind = type(current)
        if (depth > max_depth or nodes > max_nodes
                or (kind in (dict, list) and depth >= max_depth)):
            raise ConfigurationError("configuration JSON is too complex")
        if kind is dict:
            if len(current) > max_nodes - nodes:
                raise ConfigurationError("configuration JSON is too complex")
            for key, item in current.items():
                if type(key) is not str:
                    raise ConfigurationError("configuration JSON keys must be strings")
                pending.extend(((key, depth + 1), (item, depth + 1)))
            minimum_bytes += 2 + 2 * len(current)
        elif kind is list:
            if len(current) > max_nodes - nodes:
                raise ConfigurationError("configuration JSON is too complex")
            pending.extend((item, depth + 1) for item in current)
            minimum_bytes += 2 + len(current)
        elif kind is str:
            if len(current) > max_bytes:
                raise ConfigurationError("configuration file is unexpectedly large")
            try:
                minimum_bytes += len(current.encode("utf-8")) + 2
            except UnicodeError as error:
                raise ConfigurationError("configuration must be UTF-8 JSON text") from error
        elif kind is float:
            if not math.isfinite(current):
                raise ConfigurationError("configuration must not contain non-finite numbers")
            minimum_bytes += 1
        elif current is None or kind in (int, bool):
            minimum_bytes += 1
        else:
            raise ConfigurationError("configuration must contain only JSON values")
        if minimum_bytes > max_bytes:
            raise ConfigurationError("configuration file is unexpectedly large")
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(raw.encode("utf-8")) > max_bytes:
            raise ConfigurationError("configuration file is unexpectedly large")
    except (ValueError, RecursionError, OverflowError) as error:
        raise ConfigurationError("configuration JSON is too complex") from error
    return raw
