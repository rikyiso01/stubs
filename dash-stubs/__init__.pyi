from typing import Any
from dash.development.base_component import Component
from dash.dependencies import Input, Output, DashDependency
from collections.abc import Callable

class Dash:
    def __init__(self, name: str = ...) -> None: ...
    layout: Component
    def run(self, host: str = ..., port: int = ..., *, debug: bool = ...) -> None: ...
    run_server = run
    def callback[
        F: Callable[..., Any]
    ](self, *args: DashDependency) -> Callable[[F], F]: ...

__all__ = ["Input", "Output", "Dash"]
