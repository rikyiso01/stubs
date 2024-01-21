from typing import Any, TypedDict
from dash.development.base_component import Component
from plotly.graph_objects import Figure
from collections.abc import Iterable

class _Option[SC: complex | str](TypedDict):
    label: Any
    value: SC

class Graph(Component):
    def __init__(self, id: str = ..., *, figure: Figure = ...) -> None: ...

class Input(Component):
    def __init__(self, value: Any = ..., type: str = ..., *, id: str) -> None: ...

class Markdown(Component):
    def __init__(self, children: str = ..., id: str = ...) -> None: ...

class Dropdown(Component):
    def __init__[
        SC: complex | str
    ](
        self, options: Iterable[_Option[SC]] | Iterable[SC], value: SC, *, id: str
    ) -> None: ...
