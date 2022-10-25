from numpy.typing import ArrayLike, DTypeLike, NDArray
from typing import Literal, Any, overload, TypeVar

_T = TypeVar("_T", bound=DTypeLike)

def show(*, block: bool = ...) -> None: ...
def hist(
    x: ArrayLike[_T],
    bins: int = ...,
    range: tuple[int, int] = ...,
    density: bool = ...,
    weights: ArrayLike[_T] = ...,
    cumulative: bool | Literal[-1] = ...,
    bottom: ArrayLike[_T] = ...,
    histtype: Literal["bar", "barstacked", "step", "stepfilled"] = ...,
    align: Literal["left", "mid", "right"] = ...,
    orientation: Literal["vertical", "horizontal"] = ...,
    rwidth: float = ...,
    log: bool = ...,
    color: ArrayLike[_T] = ...,  # incomplete
    label: str = ...,
    stacked: bool = ...,
) -> None: ...
def xlabel(
    xlabel: str,
    fontdict: dict[str, str] = ...,  # incomplete
    labelpad: float = ...,
    *,
    loc: Literal["left", "mid", "right"] = ...,
) -> None: ...
def ylabel(
    ylabel: str,
    fontdict: dict[str, str] = ...,  # incomplete
    labelpad: float = ...,
    *,
    loc: Literal["left", "mid", "right"] = ...,
) -> None: ...
def title(
    label: str,
    fontdict: dict[str, str] = ...,  # incomplete
    loc: Literal["left", "mid", "right"] = ...,
    pad: float = ...,
    *,
    y: float = ...,
) -> None: ...
@overload
def stem(
    heads: ArrayLike[_T],
    *,
    linefmt: str = ...,
    markerfmt: str = ...,
    basefmt: str = ...,
    bottom: float = ...,
    label: str = ...,
    use_line_collection: bool = ...,
    orientation: str = ...,
    data: Any = ...,  # incomplete
) -> None: ...
@overload
def stem(
    locks: ArrayLike[_T],
    heads: ArrayLike[_T] = ...,
    *,
    linefmt: str = ...,
    markerfmt: str = ...,
    basefmt: str = ...,
    bottom: float = ...,
    label: str = ...,
    use_line_collection: bool = ...,
    orientation: str = ...,
    data: Any = ...,  # incomplete
) -> None: ...
def step(
    x: ArrayLike[_T],
    y: ArrayLike[_T] = ...,
    fmt: str = ...,
    *args: Any,
    data: Any = ...,  # incomplete
    where: Literal["pre", "post", "mid"] = ...,
) -> None: ...
@overload
def xlim(arg: tuple[float, float], /) -> None: ...
@overload
def xlim(left: float = ..., right: float = ...) -> None: ...
@overload
def ylim(arg: tuple[float, float], /) -> None: ...
@overload
def ylim(left: float, right: float = ..., /) -> None: ...
def bar(
    x: ArrayLike[_T],
    height: ArrayLike[_T],
    width: ArrayLike[_T] = ...,
    bottom: ArrayLike[_T] = ...,
    *,
    align: Literal["center", "edge"] = ...,
    data: Any = ...,  # incomplete
) -> None: ...
def plot(
    *args: ArrayLike[_T] | str,
    scalex: bool = ...,
    scaley: bool = ...,
    data: Any = ...,  # incomplete
    label: str = ...,
) -> None: ...
@overload
def legend(labels: list[str] = ..., /) -> None: ...
@overload
def legend(handles: list[Any], labels: list[str], /) -> None: ...
@overload
def legend(*, handles: list[Any]) -> None: ...
def figure(*, figsize: tuple[float, float]) -> None: ...
def subplot(nrows: int, ncols: int, index: int) -> None: ...
def grid() -> None: ...
def tight_layout() -> None: ...
def savefig(fname: str, *, type: Literal[".png"] = ...) -> None: ...
def specgram(
    x: ArrayLike[float], NFFT: int = ..., Fs: float = ...
) -> tuple[NDArray[float], NDArray[float], NDArray[float], None]: ...
def colorbar() -> None: ...
