from typing import Any, Type
from sqlalchemy.orm import Session
from .schema import (
    Acquirente,
    Appuntamento,
    Prodotto,
    UscitaMerce,
    Volontario,
    engine,
    Cliente,
    dumper,
)
from faker import Faker
from faker.providers import BaseProvider
from faker_vehicle import VehicleProvider
from random import choice, randint, random
from sqlalchemy import Table, text
from datetime import timedelta
from typing import TypeVar
from sqlalchemy.orm.decl_api import Base

T = TypeVar("T")

data: dict[Type[Base], list[Base]] = {}

BIG = 10000
NORMAL = 9000
SMALL = 5000

TABLES = [Volontario, Prodotto, Cliente, Acquirente, Appuntamento, UscitaMerce]


def insert(element: Base):
    table = type(element)
    if table not in data:
        data[table] = []
    data[table].append(element)


class ForeignKey(BaseProvider):
    def foreign_key(self, table: Type[Base]) -> Any:
        b: Base = choice(data[table])
        t: Table = b.__table__
        return getattr(b, t.columns[0].name)


class Nullable(BaseProvider):
    def null(self, v: T) -> T | None:
        if random() < 0.5:
            return v


class Standard(BaseProvider):
    def randint(self, min: int, max: int) -> int:
        return randint(min, max)

    def choice(self, elements: list[T]) -> T:
        return choice(elements)

    def money(self, max: int) -> float:
        return round(random() * max * 100) / 100


def big_data():
    with dumper(engine, "out/big_data.sql"):
        fake = Faker("it_IT")
        fake.add_provider(VehicleProvider)
        fake.add_provider(ForeignKey)
        fake.add_provider(Nullable)
        fake.add_provider(Standard)
        for i in range(SMALL):
            insert(
                Volontario(
                    cod_fisc=fake.unique.ssn(),
                    veicolo=fake.null(fake.vehicle_category()),
                    datan=fake.date_of_birth(minimum_age=16, maximum_age=100),
                    luogon=fake.city(),
                    sesso=fake.choice("mf"),
                    cognome=fake.last_name(),
                    nome=fake.first_name(),
                )
            )
        fake.unique.clear()
        for i in range(SMALL):
            insert(
                Prodotto(
                    nome_prodotto=fake.unique.file_name(extension=""),
                    punti=fake.randint(1, 30),
                    quantita=fake.randint(0, 100),
                    post_scadenza=fake.null(fake.time_delta(timedelta(days=60))),
                    tipologia_prodotto=fake.file_name(extension=""),
                )
            )
        acquirenti: list[str] = []
        for i in range(SMALL):
            sm = randint(30, 60)
            acquirenti.append(fake.unique.ssn())
            insert(
                Cliente(
                    codcli=i,
                    saldo=fake.randint(0, sm),
                    punti_mensili=sm,
                    ente=fake.company(),
                    inizio_autorizzazione=fake.date_between("-6M"),
                    acquirente=acquirenti[i],
                )
            )
        fake.unique.clear()
        for i in range(SMALL):
            insert(
                Acquirente(
                    cod_fisc=acquirenti[i],
                    datan=fake.date_of_birth(minimum_age=16, maximum_age=100),
                    luogon=fake.city(),
                    sesso=fake.choice("mf"),
                    nome=fake.first_name(),
                    cognome=fake.last_name(),
                    cliente=i,
                )
            )
        fake.unique.clear()
        for i in range(BIG):
            pi = randint(0, 60)
            insert(
                Appuntamento(
                    dataora=fake.unique.date_time_between("-5y"),
                    punti_finali=fake.null(randint(0, pi)),
                    punti_iniziali=pi,
                    volontario=fake.foreign_key(Volontario),
                    acquirente=fake.foreign_key(Acquirente),
                )
            )
        fake.unique.clear()
        for _ in range(NORMAL):
            insert(
                UscitaMerce(
                    nome_prodotto=fake.foreign_key(Prodotto),
                    appuntamento=fake.unique.foreign_key(Appuntamento),
                    quantita=fake.randint(1, 30),
                )
            )
        with Session(engine) as session:
            session.execute(text("SET CONSTRAINTS ALL DEFERRED"))
            for table in reversed(Base.metadata.tables.values()):
                session.query(table).delete()
            session.commit()
        with Session(engine) as session:
            session.execute(text("SET CONSTRAINTS ALL DEFERRED"))
            for table in TABLES:
                session.execute(
                    text(
                        f"ALTER TABLE {table.__table__.name} ADD COLUMN IF NOT EXISTS dummy text"
                    )
                )
            session.flush()
            for values in data.values():
                print(values[0].__table__.name)
                session.add_all(values)
                session.flush()
            session.commit()
