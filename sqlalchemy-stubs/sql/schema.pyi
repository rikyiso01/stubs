from sqlalchemy.engine.base import Engine
from sqlalchemy import Table

class MetaData:
    def create_all(self, bind: Engine) -> None: ...
    tables: dict[str, Table]
