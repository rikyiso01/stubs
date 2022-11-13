from numpy.typing import ArrayLike, DTypeLike, NDArray
from typing import Literal, Any, overload, TypeVar
from matplotlib.colors import Colormap
from matplotlib.figure import Figure
from matplotlib.axes import Axes
from matplotlib import cm as cm

_T = TypeVar("_T", bound=DTypeLike)

_axes: Axes
_figure: Figure

hist = _axes.hist
ticklabel_format = _axes.ticklabel_format
xlabel = _axes.set_xlabel
ylabel = _axes.set_ylabel
xlim = _axes.set_xlim
ylim = _axes.set_ylim
xticks = _axes.set_xticks
yticks = _axes.set_yticks
plot = _axes.plot
title = _axes.set_title
subplot = _figure.add_subplot
tight_layout = _figure.tight_layout

def show(*, block: bool = ...) -> None: ...
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
def bar(
    x: ArrayLike[_T],
    height: ArrayLike[_T],
    width: ArrayLike[_T] = ...,
    bottom: ArrayLike[_T] = ...,
    *,
    align: Literal["center", "edge"] = ...,
    data: Any = ...,  # incomplete
) -> None: ...
@overload
def legend(labels: list[str] = ..., /) -> None: ...
@overload
def legend(handles: list[Any], labels: list[str], /) -> None: ...
@overload
def legend(*, handles: list[Any]) -> None: ...
def figure(*, figsize: tuple[float, float] = ...) -> Figure: ...
def grid() -> None: ...
def savefig(fname: str, *, type: Literal[".png"] = ...) -> None: ...
def specgram(
    x: ArrayLike[float], NFFT: int = ..., Fs: float = ...
) -> tuple[NDArray[float], NDArray[float], NDArray[float], None]: ...
def colorbar(*, orientation: Literal["vertical"] = ...) -> None: ...
def imread(fname: str) -> NDArray[float]: ...
def imshow(
    X: ArrayLike[complex],
    cmap: Literal["gray", "Reds", "Greens", "Blues", "hsv"] | Colormap | None = ...,
) -> None: ...
def axis(option: Literal["off"], /) -> None: ...
@overload
def subplots() -> tuple[Figure, Axes]: ...
@overload
def subplots(nrows: int) -> tuple[Figure, tuple[Axes, Axes]]: ...
@overload
def subplots(*, ncols: int) -> tuple[Figure, tuple[Axes, Axes]]: ...
@overload
def subplots(
    nrows: int, ncols: int
) -> tuple[Figure, tuple[tuple[Axes, Axes], tuple[Axes, Axes]]]: ...
