from .schema import engine
from sqlalchemy import text
from sqlalchemy.orm import Session
from .big_data import TABLES


def table_size() -> list[list[str]]:
    result: list[list[str]] = []
    with Session(engine) as session:
        session.execute(text("analyze"))
        session.flush()
        for table in TABLES:
            pages = session.execute(
                text(
                    f"select relpages,reltuples from pg_class where relname='{table.__table__.name}'"
                )
            ).first()
            assert pages is not None
            result.append(
                [
                    table.__table__.name,
                    str(int(pages.reltuples)),
                    str(pages.relpages),
                ]
            )
    return result
