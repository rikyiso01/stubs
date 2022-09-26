from typing import Literal
from numpy.typing import ArrayLike, DTypeLike

class Figure:
    def add_histogram(
        self,
        *,
        x: ArrayLike[DTypeLike] = ...,
        y: ArrayLike[DTypeLike] = ...,
        nbinsx: int = ...,
        histfunc: Literal["sum", "count"] = ...,
        name: str = ...,
    ) -> Figure: ...
    def update_layout(
        self, *, xaxis_title: str = ..., yaxis_title: str = ..., title: str = ...
    ) -> Figure: ...
    def show(self) -> None: ...
    def add_scatter(
        self,
        *,
        x: ArrayLike[DTypeLike] = ...,
        y: ArrayLike[DTypeLike] = ...,
        name: str = ...,
        mode: Literal["lines", "markers", "lines+markes", "markers+lines"] = ...,
        line_shape: Literal["linear", "spline", "hv", "vh", "hvh", "vhv"] = ...,
    ) -> Figure: ...
    def update_xaxes(self, *, title_text: str = ...) -> Figure: ...
    def update_yaxes(self, *, title_text: str = ...) -> Figure: ...
