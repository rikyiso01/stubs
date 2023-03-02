from typing import TypeVar, Generic

_K = TypeVar("_K")

class PlotAccessor(Generic[_K]):
    def __call__(
        self, kind: str = ..., x: _K = ..., figsize: tuple[int, int] = ...
    ) -> None:
        pass
    def bar(
        self, x: _K | None = ..., y: _K | None = ..., *, figsize: tuple[int, int] = ...
    ) -> PlotAccessor[_K]: ...
