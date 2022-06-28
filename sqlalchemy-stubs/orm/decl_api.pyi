from pydantic import BaseModel
from ..sql.schema import MetaData
from .. import CheckConstraint, Table

class Base(BaseModel):
    metadata: MetaData
    __tablename__: str
    __table_args__: tuple[CheckConstraint, ...]
    __table__: Table
