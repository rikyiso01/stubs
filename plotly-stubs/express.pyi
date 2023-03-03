from typing import Any, Literal
from plotly.graph_objects import Figure
from typing import overload
from numpy.typing import ArrayLike, DTypeLike
from mte.typevar import T, F
from mte.pandas import DataFrameLike

def bar(
    data_frame: DataFrameLike[T, Any, Any] = ...,
    x: T = ...,
    y: T = ...,
    color: T = ...,
    *,
    barmode: Literal["relative", "group"] = ...
) -> Figure: ...
@overload
def line(
    *, x: ArrayLike[DTypeLike] = ..., y: ArrayLike[DTypeLike], title: str = ...
) -> Figure: ...
@overload
def line(
    data_frame: DataFrameLike[T, Any, Any],
    x: T = ...,
    y: T = ...,
    color: T = ...,
    title: str = ...,
) -> Figure: ...
def imshow(
    img: ArrayLike[F], *, animation_frame: int = ..., facet_col: int = ...
) -> Figure: ...
