from typing import Any
from strawberry.types import Info
from abc import ABC, abstractmethod

class BasePermission(ABC):
    @abstractmethod
    def has_permission(self, source: Any, info: Info, /) -> bool: ...
