from matplotlib.artist import Artist
from numpy.typing import ArrayLike, DTypeLike
from typing import Literal, overload, Any
from matplotlib.colors import Colormap

class _AxesBase(Artist): ...

class Axes(_AxesBase):
    def twinx(self) -> Axes: ...
    def imshow(
        self,
        X: ArrayLike[complex],
        cmap: Literal["gray", "Reds", "Greens", "Blues", "hsv"] | Colormap | None = ...,
    ) -> None: ...
    def set_axis_off(self) -> None: ...
    def hist(
        self,
        x: ArrayLike[DTypeLike],
        bins: int = ...,
        range: tuple[int, int] = ...,
        density: bool = ...,
        weights: ArrayLike[DTypeLike] = ...,
        cumulative: bool | Literal[-1] = ...,
        bottom: ArrayLike[DTypeLike] = ...,
        histtype: Literal["bar", "barstacked", "step", "stepfilled"] = ...,
        align: Literal["left", "mid", "right"] = ...,
        orientation: Literal["vertical", "horizontal"] = ...,
        rwidth: float = ...,
        log: bool = ...,
        color: ArrayLike[DTypeLike] = ...,  # incomplete
        label: str = ...,
        stacked: bool = ...,
    ) -> None: ...
    def ticklabel_format(
        self,
        *,
        axis: Literal["both", "x", "y"] = ...,
        style: Literal["sci", "scientific", "plain", ""] = ...,
        scilimits: tuple[int, int] | None = ...,
    ) -> None: ...
    def set_xlabel(
        self,
        xlabel: str,
        fontdict: dict[str, str] = ...,  # incomplete
        labelpad: float = ...,
        *,
        loc: Literal["left", "mid", "right"] = ...,
    ) -> None: ...
    def set_ylabel(
        self,
        ylabel: str,
        fontdict: dict[str, str] = ...,  # incomplete
        labelpad: float = ...,
        *,
        loc: Literal["left", "mid", "right"] = ...,
    ) -> None: ...
    @overload
    def set_xlim(self, arg: tuple[float, float], /) -> None: ...
    @overload
    def set_xlim(self, left: float = ..., right: float = ...) -> None: ...
    @overload
    def set_ylim(self, arg: tuple[float, float], /) -> None: ...
    @overload
    def set_ylim(self, left: float, right: float = ..., /) -> None: ...
    def get_xlim(self) -> tuple[float, float]: ...
    def get_ylim(self) -> tuple[float, float]: ...
    def set_xticks(self, ticks: ArrayLike[float]) -> None: ...
    def set_yticks(self, ticks: ArrayLike[float]) -> None: ...
    def plot(
        self,
        *args: ArrayLike[DTypeLike] | str,
        scalex: bool = ...,
        scaley: bool = ...,
        data: Any = ...,  # incomplete
        label: str = ...,
    ) -> None: ...
    def set_title(
        self,
        label: str,
        fontdict: dict[str, str] = ...,  # incomplete
        loc: Literal["left", "mid", "right"] = ...,
        pad: float = ...,
        *,
        y: float = ...,
    ) -> None: ...
