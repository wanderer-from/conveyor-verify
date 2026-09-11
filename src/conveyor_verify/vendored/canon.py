"""RFC 8785 (JCS) canonicalization with the signed-content restrictions of integrity.md §1.

Signed content contains no floats (decimals are strings), no nulls (absent
field != null), and only string keys. Canonicalization itself is delegated to
the `rfc8785` package and never hand-rolled.
"""

from __future__ import annotations

from typing import Any

import rfc8785

Json = dict[str, Any] | list[Any] | str | int | bool


class NotSignableError(ValueError):
    """The value violates the signed-content rules (float, null, non-string key)."""


def assert_signable(value: Any, path: str = "$") -> None:
    """Raise NotSignableError if `value` may not appear in signed content."""
    if value is None:
        raise NotSignableError(f"{path}: null is not allowed in signed content")
    if isinstance(value, bool | int | str):
        return
    if isinstance(value, float):
        raise NotSignableError(f"{path}: floats are not allowed in signed content; use a string")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotSignableError(f"{path}: object keys must be strings, got {type(key).__name__}")
            assert_signable(item, f"{path}.{key}")
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            assert_signable(item, f"{path}[{index}]")
        return
    raise NotSignableError(f"{path}: unsupported type {type(value).__name__}")


def canonicalize(value: Json) -> bytes:
    """Return the JCS canonical UTF-8 bytes of `value` after checking signability."""
    assert_signable(value)
    result: bytes = rfc8785.dumps(value)
    return result
