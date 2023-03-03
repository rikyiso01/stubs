from typing import Any, Generic, TypedDict, TypeVar
from dash.development.base_component import Component
from plotly.graph_objects import Figure
from collections.abc import Iterable

_SC = TypeVar("_SC", bound=complex | str)

class _Option(TypedDict, Generic[_SC]):
    label: Any
    value: _SC

class Graph(Component):
    def __init__(self, id: str = ..., *, figure: Figure = ...) -> None: ...

class Input(Component):
    def __init__(self, value: Any = ..., type: str = ..., *, id: str) -> None: ...

class Markdown(Component):
    def __init__(self, children: str = ..., id: str = ...) -> None: ...

class Dropdown(Component):
    def __init__(
        self, options: Iterable[_Option[_SC]] | Iterable[_SC], value: _SC, *, id: str
    ) -> None: ...
