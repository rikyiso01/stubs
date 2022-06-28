from ..engine.base import Engine
from .. import Table

class MetaData:
    def create_all(self, bind: Engine) -> None: ...
    tables: dict[str, Table]
