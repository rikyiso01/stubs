from __future__ import annotations
from typing import Protocol
from collections.abc import Sequence
from mte.numpy import Array


class SeriesLike[K, V](Protocol):
    def __getitem__(self, item: K, /) -> V:
        ...

    def __len__(self) -> int:
        ...

    def __contains__(self, item: K, /) -> bool:
        ...


type SeriesCompatible[K, V] = SeriesLike[K, V] | Sequence[V] | Array[V]


class DataFrameLike[K, K2, V](Protocol):
    def __getitem__(self, item: K, /) -> SeriesLike[K2, V]:
        ...

    def __len__(self) -> int:
        ...

    def __contains__(self, item: K, /) -> bool:
        ...
