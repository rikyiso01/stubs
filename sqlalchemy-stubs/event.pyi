from typing import Any, Literal
from .engine.base import Engine
from collections.abc import Callable

def listens_for(
    engine: Engine, event: Literal["before_cursor_execute"]
) -> Callable[
    [
        Callable[
            [Any, Any, str, dict[str, Any] | tuple[dict[str, Any], ...], Any, Any], Any
        ],
    ],
    None,
]: ...
