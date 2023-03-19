from __future__ import annotations
from typing import Protocol
from collections.abc import Sequence
from mte.typevar import K_con, V_co, V, K, K2_con
from mte.numpy import Array
from typing_extensions import TypeAlias


class SeriesLike(Protocol[K_con, V_co]):
    def __getitem__(self, item: K_con, /) -> V_co:
        ...

    def __len__(self) -> int:
        ...

    def __contains__(self, item: K_con, /) -> bool:
        ...


SeriesCompatible: TypeAlias = "SeriesLike[K, V] | Sequence[V] | Array[V]"


class DataFrameLike(Protocol[K_con, K2_con, V_co]):
    def __getitem__(self, item: K_con, /) -> SeriesLike[K2_con, V_co]:
        ...

    def __len__(self) -> int:
        ...

    def __contains__(self, item: K_con, /) -> bool:
        ...
