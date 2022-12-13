from typing import Any, Literal
from plotly.graph_objects import Figure
from pandas import DataFrame
from typing import TypeVar, overload
from numpy.typing import ArrayLike, DTypeLike

_T = TypeVar("_T")

def bar(
    data_frame: DataFrame[_T, Any, Any] = ...,
    x: _T = ...,
    y: _T = ...,
    color: _T = ...,
    *,
    barmode: Literal["relative", "group"] = ...
) -> Figure: ...
@overload
def line(
    *, x: ArrayLike[DTypeLike] = ..., y: ArrayLike[DTypeLike], title: str = ...
) -> Figure: ...
@overload
def line(
    data_frame: DataFrame[_T, Any, Any],
    x: _T = ...,
    y: _T = ...,
    color: _T = ...,
    title: str = ...,
) -> Figure: ...
def imshow(
    img: ArrayLike[int], *, animation_frame: int = ..., facet_col: int = ...
) -> Figure: ...
