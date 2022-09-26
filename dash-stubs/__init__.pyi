from typing import Any, TypeVar
from .development.base_component import Component
from .dependencies import Input, Output
from collections.abc import Callable
from .dependencies import DashDependency

_T = TypeVar("_T", bound=Callable[..., Any])

class Dash:
    def __init__(self, name: str = ...) -> None: ...
    layout: Component
    def run(self, host: str = ..., port: int = ..., *, debug: bool = ...) -> None: ...
    run_server = run
    def callback(self, *args: DashDependency) -> Callable[[_T], _T]: ...

__all__ = ["Input", "Output", "Dash"]
