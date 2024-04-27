from sqlalchemy.sql.schema import MetaData
from sqlalchemy import CheckConstraint, Table, Column
from typing_extensions import dataclass_transform

@dataclass_transform(kw_only_default=True, field_specifiers=(Column,))
class Base:
    metadata: MetaData = ...
    __tablename__: str
    __table_args__: tuple[CheckConstraint, ...] = ...
    __table__: Table = ...

