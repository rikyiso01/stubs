from dash.development.base_component import Component
from typing import Any, TypeVar, TypedDict, Generic

_T = TypeVar("_T")

class _Column(TypedDict, Generic[_T]):
    name: Any
    id: _T

class DataTable(Component):
    def __init__(
        self,
        data: list[dict[_T, Any]] = ...,
        columns: list[_Column[_T]] = ...,
        *,
        id: str = ...
    ) -> None: ...
