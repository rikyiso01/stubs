from dash.development.base_component import Component
from typing import Any, TypedDict, Generic
from mte.typevar import T

class _Column(TypedDict, Generic[T]):
    name: Any
    id: T

class DataTable(Component):
    def __init__(
        self,
        data: list[dict[T, Any]] = ...,
        columns: list[_Column[T]] = ...,
        *,
        id: str = ...
    ) -> None: ...
