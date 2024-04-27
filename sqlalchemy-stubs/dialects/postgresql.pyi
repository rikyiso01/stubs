from sqlalchemy.engine.interfaces import Dialect


def dialect() -> Dialect: ...

JSONB=dict[str,JSONB]|list[JSONB]|str|int|bool|float

