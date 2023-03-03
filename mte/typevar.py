from typing import TypeVar, Any
from typing_extensions import TypeVarTuple
from collections.abc import Callable

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)
T_con = TypeVar("T_con", contravariant=True)
T2 = TypeVar("T2")
K = TypeVar("K")
K_con = TypeVar("K_con", contravariant=True)
K2 = TypeVar("K2")
K2_con = TypeVar("K2_con", contravariant=True)
K3 = TypeVar("K3")
V = TypeVar("V")
V_co = TypeVar("V_co", covariant=True)
V2 = TypeVar("V2")

I = TypeVar("I", bound=int)
I2 = TypeVar("I2", bound=int)
F = TypeVar("F", bound=float)
F2 = TypeVar("F2", bound=float)
C = TypeVar("C", bound=complex)
C2 = TypeVar("C2", bound=complex)

TT = TypeVarTuple("TT")

Func = TypeVar("Func", bound=Callable[..., Any])
