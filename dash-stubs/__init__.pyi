from typing import Any, TypeVar
from dash.development.base_component import Component
from dash.dependencies import Input, Output,DashDependency
from collections.abc import Callable

_T = TypeVar("_T", bound=Callable[..., Any])

class Dash:
    def __init__(self, name: str = ...) -> None: ...
    layout: Component
    def run(self, host: str = ..., port: int = ..., *, debug: bool = ...) -> None: ...
    run_server = run
    def callback(self, *args: DashDependency) -> Callable[[_T], _T]: ...

__all__ = ["Input", "Output", "Dash"]
