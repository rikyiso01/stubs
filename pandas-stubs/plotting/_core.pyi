from typing import Generic
from mte.typevar import K

class PlotAccessor(Generic[K]):
    def __call__(
        self, kind: str = ..., x: K = ..., figsize: tuple[int, int] = ...
    ) -> None:
        pass
    def bar(
        self, x: K | None = ..., y: K | None = ..., *, figsize: tuple[int, int] = ...
    ) -> PlotAccessor[K]: ...
