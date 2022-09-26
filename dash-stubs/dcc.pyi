from typing import Any, Generic, TypeVar, TypedDict
from .development.base_component import Component
from plotly.graph_objects import Figure
from collections.abc import Iterable

_T = TypeVar("_T", bound=str | complex)

class _Option(TypedDict, Generic[_T]):
    label: Any
    value: _T

class Graph(Component):
    def __init__(self, id: str = ..., *, figure: Figure = ...) -> None: ...

class Input(Component):
    def __init__(self, value: Any = ..., type: str = ..., *, id: str) -> None: ...

class Markdown(Component):
    def __init__(self, children: str = ..., id: str = ...) -> None: ...

class Dropdown(Component):
    def __init__(
        self, options: Iterable[_Option[_T]] | Iterable[_T], value: _T, *, id: str
    ) -> None: ...
