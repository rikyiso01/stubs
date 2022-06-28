from ..engine.result import ScalarResult
from ..engine.cursor import CursorResult
from ..engine.base import Engine
from .decl_api import Base
from contextlib import AbstractContextManager
from typing import Type, Any
from ..sql.elements import TextClause
from ..sql.selectable import Select
from .query import Query
from .. import Table

_Stmt = TextClause | Select

class Session(AbstractContextManager[Session]):
    def __init__(self, engine: Engine) -> None: ...
    def commit(self) -> None: ...
    def add_all(self, instances: list[Base]) -> None: ...
    def add(self, instance: Base) -> None: ...
    def execute(self, statement: _Stmt) -> CursorResult: ...
    def scalar(self, statement: _Stmt) -> Any: ...
    def scalars(self, statement: _Stmt) -> ScalarResult: ...
    def query(self, table: Table) -> Query: ...
    def flush(self) -> None: ...

def declarative_base() -> Type[Base]: ...