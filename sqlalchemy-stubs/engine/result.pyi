from typing import Any
from collections.abc import Iterator

class ScalarResult:
    def __iter__(self) -> Iterator[Any]: ...
