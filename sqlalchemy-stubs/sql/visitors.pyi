from sqlalchemy.sql.compiler import StrSQLCompiler
from sqlalchemy.engine.interfaces import Dialect

class Traversible:
    def compile(self, *, dialect: Dialect) -> StrSQLCompiler: ...
