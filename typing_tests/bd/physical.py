from .schema import dumper, engine
from sqlalchemy.orm import Session
from sqlalchemy import text

IDS = [4, 8, 12]


def physical():
    with dumper(engine, "out/fisico.sql"):
        with Session(engine) as session:
            source = [""]
            for id in IDS:
                session.execute(text(source[id]))
            session.commit()
