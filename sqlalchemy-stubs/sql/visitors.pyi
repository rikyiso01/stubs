from .compiler import StrSQLCompiler
from ..engine.interfaces import Dialect

class Traversible:
    def compile(self, *, dialect: Dialect) -> StrSQLCompiler: ...
