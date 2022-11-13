from dataclasses import dataclass
from typing import Any, Type, TypeVar, Iterable
from collections.abc import Callable
from strawberry.permission import BasePermission

_T = TypeVar("_T")

type = dataclass

def field(
    resolver: Callable[..., _T], *, permission_classes: Iterable[Type[BasePermission]]
) -> _T: ...

class Schema:
    def __init__(
        self, query: Type[Any], mutation: Type[Any] = ..., subscription: Type[Any] = ...
    ) -> None: ...

def union(name: str, types: Iterable[Type[_T]]) -> Type[_T]: ...
