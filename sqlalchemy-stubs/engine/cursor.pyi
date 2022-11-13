from collections.abc import Iterator
from sqlalchemy.engine.row import Row
from sqlalchemy.engine.result import ScalarResult
from typing import Any

class CursorResult:
    def first(self) -> Row | None: ...
    def __iter__(self) -> Iterator[Row]: ...
    def scalar(self) -> Any: ...
    def scalars(self) -> ScalarResult: ...
