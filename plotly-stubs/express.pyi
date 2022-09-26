from typing import Any, Literal
from plotly.graph_objects import Figure
from pandas import DataFrame
from typing import TypeVar

_T = TypeVar("_T")

def bar(
    data_frame: DataFrame[_T, Any, Any] = ...,
    x: _T = ...,
    y: _T = ...,
    color: _T = ...,
    *,
    barmode: Literal["relative", "group"] = ...
) -> Figure: ...
def line(
    data_frame: DataFrame[_T, Any, Any] = ..., x: _T = ..., y: _T = ..., color: _T = ...
) -> Figure: ...
