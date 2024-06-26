from dash.development.base_component import Component
from typing import Any, TypedDict

class _Column[T](TypedDict):
    name: Any
    id: T

class DataTable(Component):
    def __init__[
        T
    ](
        self,
        data: list[dict[T, Any]] = ...,
        columns: list[_Column[T]] = ...,
        *,
        id: str = ...,
    ) -> None: ...
