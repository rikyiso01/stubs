from MySQLdb._mysql import result
from typing import Type
from types import TracebackType
from mte.protocols import ContextManager

def connect(*, host: str, port: int, user: str, passwd: str) -> Connection: ...

class Connection(ContextManager[Connection]):
    def query(self, query: str) -> None: ...
    def store_result(self) -> result: ...
    def __enter__(self) -> Connection: ...
    def __exit__(
        self,
        __exc_type: Type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
        /,
    ) -> (bool | None): ...
