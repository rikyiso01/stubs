from typing import Any
from collections.abc import Callable

class UniqueProxy:
    def clear(self) -> None: ...
    def __getattr__(self, attr: str) -> Callable[..., Any]: ...
