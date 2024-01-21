from dataclasses import dataclass
from typing import Any, Type, Iterable
from collections.abc import Callable
from strawberry.permission import BasePermission

type = dataclass

def field[
    T
](
    resolver: Callable[..., T], *, permission_classes: Iterable[Type[BasePermission]]
) -> T: ...

class Schema:
    def __init__(
        self, query: Type[Any], mutation: Type[Any] = ..., subscription: Type[Any] = ...
    ) -> None: ...

def union[T](name: str, types: Iterable[Type[T]]) -> Type[T]: ...
