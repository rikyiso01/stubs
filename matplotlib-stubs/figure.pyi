from matplotlib.artist import Artist
from matplotlib.axes import Axes
from typing import overload

class FigureBase(Artist): ...

class Figure(FigureBase):
    def set_figheight(self, val: float, forward: bool = ...) -> None: ...
    def set_figwidth(self, val: float, forward: bool = ...) -> None: ...
    @overload
    def add_subplot(
        self,
        nrows: int,
        ncols: int,
        index: int,
        *,
        sharex: Axes | None = ...,
        sharey: Axes | None = ...
    ) -> Axes: ...
    @overload
    def add_subplot(self, pos: int) -> Axes: ...
    def tight_layout(self) -> None: ...
