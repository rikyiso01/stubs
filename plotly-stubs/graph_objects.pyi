from typing import Literal
from numpy.typing import ArrayLike, DTypeLike

class Figure:
    def add_histogram(
        self,
        *args: None,
        x: ArrayLike[DTypeLike] = ...,
        y: ArrayLike[DTypeLike] = ...,
        nbinsx: int = ...
    ) -> Figure: ...
    def update_layout(
        self,
        *args: None,
        xaxis_title: str = ...,
        yaxis_title: str = ...,
        title: str = ...
    ) -> Figure: ...
    def show(self) -> None: ...
    def add_scatter(
        self,
        *args: None,
        x: ArrayLike[DTypeLike] = ...,
        y: ArrayLike[DTypeLike] = ...,
        name: str = ...,
        mode: Literal["lines", "markers", "lines+markes", "markers+lines"] = ...,
        line_shape: Literal["linear", "spline", "hv", "vh", "hvh", "vhv"] = ...
    ) -> Figure: ...
    def update_xaxes(self, *args: None, title_text: str = ...) -> Figure: ...
    def update_yaxes(self, *args: None, title_text: str = ...) -> Figure: ...
