from __future__ import annotations
from contextlib import contextmanager
from datetime import date, datetime, timedelta, time
from typing import Any, Optional
from collections.abc import Generator
from sqlalchemy.engine.base import Engine
from sqlalchemy import (
    Column,
    String,
    CHAR,
    CheckConstraint,
    Numeric,
    Integer,
    Interval,
    ForeignKey,
    Date,
    DateTime,
    Time,
    create_engine,
    text,
    event,
)
from sqlalchemy.orm import declarative_base, Session

Base = declarative_base()

engine = create_engine(
    "postgresql://postgres:schumi2001@localhost",
    future=True,
    echo=True,
    connect_args={"options": "-csearch_path=socialmarket"},
)

SIZE = 50


class Donatore(Base):
    __tablename__ = "donatori"
    __table_args__ = (CheckConstraint("tipologia in ('p','a','c')"),)
    codfisc: str = Column(CHAR(16), primary_key=True)
    tipologia: str = Column(CHAR(1), nullable=False)


class Volontario(Base):
    __tablename__: str = "volontari"
    __table_args__ = (CheckConstraint("sesso in ('m','f')"),)
    cod_fisc: str = Column(CHAR(16), primary_key=True)
    veicolo: Optional[str] = Column(String(SIZE), default=None)
    datan: date = Column(Date, nullable=False)
    luogon: str = Column(String(SIZE), nullable=False)
    sesso: str = Column(CHAR(1), nullable=False)
    cognome: str = Column(String(SIZE), nullable=False)
    nome: str = Column(String(SIZE), nullable=False)


class Prodotto(Base):
    __tablename__: str = "prodotti"
    __table_args__ = (CheckConstraint("punti between 1 and 60"),)
    nome_prodotto: str = Column(String(SIZE), primary_key=True)
    punti: int = Column(Numeric(2, 0), nullable=False)
    quantita: int = Column(Integer, nullable=False)
    post_scadenza: Optional[timedelta] = Column(Interval, default=None)
    tipologia_prodotto: str = Column(String(SIZE), nullable=False)


class Cliente(Base):
    __tablename__: str = "clienti"
    __table_args__ = (
        CheckConstraint("saldo between 0 and 60"),
        CheckConstraint("punti_mensili between 30 and 60"),
        CheckConstraint("saldo<=punti_mensili"),
    )
    codcli: int = Column(Integer, primary_key=True)
    saldo: int = Column(Numeric(2, 0), nullable=False)
    punti_mensili: int = Column(Numeric(2, 0), nullable=False)
    ente: str = Column(String(SIZE), nullable=False)
    inizio_autorizzazione: date = Column(Date, nullable=False)
    acquirente: str = Column(
        ForeignKey("acquirenti.cod_fisc", deferrable=True), nullable=False, unique=True
    )


class Acquirente(Base):
    __tablename__: str = "acquirenti"
    __table_args__ = (CheckConstraint("sesso in ('m','f')"),)
    cod_fisc: str = Column(CHAR(16), primary_key=True)
    datan: date = Column(Date, nullable=False)
    luogon: str = Column(String(SIZE), nullable=False)
    sesso: str = Column(CHAR(1), nullable=False)
    nome: str = Column(String(SIZE), nullable=False)
    cognome: str = Column(String(SIZE), nullable=False)
    cliente: int = Column(ForeignKey(Cliente.codcli, deferrable=True), nullable=False)


class ContattoAcquirente(Base):
    __tablename__: str = "contatti_acquirenti"
    valore: str = Column(String(SIZE), nullable=False, primary_key=True)
    acquirente: str = Column(
        ForeignKey(Acquirente.cod_fisc), primary_key=True, nullable=False
    )


class IngressoMerce(Base):
    __tablename__: str = "ingresso_merci"
    dataora: datetime = Column(DateTime, primary_key=True)
    importo: Optional[int] = Column(Numeric(20, 2), default=None)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), nullable=False)


class Donazione(Base):
    __tablename__: str = "donazioni"
    __table_args__ = (
        CheckConstraint("ingresso_merci is not null or importo is not null"),
    )
    data: date = Column(Date, primary_key=True)
    donatore: str = Column(ForeignKey(Donatore.codfisc), primary_key=True)
    importo: Optional[int] = Column(Numeric(20, 2), default=None)
    ingresso_merci: Optional[datetime] = Column(
        ForeignKey(IngressoMerce.dataora), default=None
    )


class Trasporto(Base):
    __tablename__: str = "trasporti"
    dataora: datetime = Column(DateTime, primary_key=True)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), primary_key=True)
    civico: str = Column(CHAR(16), nullable=False)
    via: str = Column(String(SIZE), nullable=False)
    cap: int = Column(Numeric(5, 0), nullable=False)
    nscatole: int = Column(Integer, nullable=False)
    ingresso_merci: Optional[datetime] = Column(
        ForeignKey(IngressoMerce.dataora), default=None
    )


class Disponibilita(Base):
    __tablename__: str = "disponibilita"
    __table_args__ = (CheckConstraint("giornosettimana between 1 and 7"),)
    orainizio: time = Column(Time, primary_key=True)
    giornosettimana: int = Column(Numeric(1, 0), primary_key=True)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), primary_key=True)
    durata: timedelta = Column(Interval, nullable=False)


class Turno(Base):
    __tablename__: str = "turni"
    inizio: datetime = Column(DateTime, primary_key=True)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), primary_key=True)
    durata: timedelta = Column(Interval, nullable=False)


class TipoServizio(Base):
    __tablename__: str = "tipi_servizi"
    __table_args__ = (CheckConstraint("tiposervizio in ('t','a')"),)
    tiposervizio: str = Column(CHAR(1), primary_key=True)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), primary_key=True)


class FasciaEta(Base):
    __tablename__: str = "fasce_eta"
    __table_args__ = (CheckConstraint("fascia_eta between 0 and 5"),)
    fascia_eta: int = Column(Numeric(1, 0), primary_key=True)
    cliente: int = Column(ForeignKey(Cliente.codcli), primary_key=True)
    numero_membri: int = Column(Integer, nullable=False)


class Appuntamento(Base):
    __tablename__: str = "appuntamenti"
    __table_args__ = (
        CheckConstraint("punti_finali between 0 and 60"),
        CheckConstraint("punti_iniziali between 0 and 60"),
        CheckConstraint("punti_finali<=punti_iniziali or punti_finali is null"),
    )

    dataora: datetime = Column(DateTime, primary_key=True)
    punti_finali: Optional[int] = Column(Numeric(2, 0), default=None)
    punti_iniziali: int = Column(Numeric(2, 0), nullable=False)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), nullable=False)
    acquirente: str = Column(ForeignKey(Acquirente.cod_fisc), nullable=False)


class Scarico(Base):
    __tablename__: str = "scarichi"
    data: date = Column(Date, primary_key=True)
    nome_prodotto: str = Column(ForeignKey(Prodotto.nome_prodotto), primary_key=True)
    quantita: int = Column(Integer, nullable=False)


class ProdottoDeperibile(Base):
    __tablename__: str = "prodotti_deperibili"
    id: int = Column(Integer, primary_key=True)
    nome_prodotto: str = Column(ForeignKey(Prodotto.nome_prodotto), primary_key=True)
    data_scadenza: date = Column(Date, nullable=False)


class UscitaMerce(Base):
    __tablename__: str = "uscita_merce"
    nome_prodotto: str = Column(ForeignKey(Prodotto.nome_prodotto), primary_key=True)
    appuntamento: datetime = Column(ForeignKey(Appuntamento.dataora), primary_key=True)
    quantita: int = Column(Integer, nullable=False)


class IngressoProdotto(Base):
    __tablename__: str = "ingresso_prodotti"
    nome_prodotto: str = Column(ForeignKey(Prodotto.nome_prodotto), primary_key=True)
    ingresso_merci: datetime = Column(
        ForeignKey(IngressoMerce.dataora), primary_key=True
    )
    quantita: int = Column(Integer, nullable=False)


class ContattoDonatore(Base):
    __tablename__: str = "contatti_donatori"
    valore: str = Column(String(SIZE), primary_key=True)
    donatore: str = Column(ForeignKey(Donatore.codfisc), primary_key=True)


class ContattoVolontario(Base):
    __tablename__: str = "contatti_volontari"
    valore: str = Column(String(SIZE), primary_key=True)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), primary_key=True)


class Associazioni(Base):
    __tablename__: str = "associazioni"
    nome: str = Column(String(SIZE), primary_key=True)
    volontario: str = Column(ForeignKey(Volontario.cod_fisc), primary_key=True)


@contextmanager
def dumper(engine: Engine, file: str) -> Generator[None, None, None]:
    def callback(
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: dict[str, Any] | tuple[dict[str, Any], ...],
        context: Any,
        executemany: Any,
    ) -> None:
        if not isinstance(parameters, tuple):
            p = (parameters,)
        else:
            p = parameters
        for parameter in p:
            parameter = parameter.copy()
            for key, value in parameter.items():
                if value is None:
                    value = "null"
                else:
                    value = "'" + str(value).replace("'", "''") + "'"
                parameter[key] = value
            result = statement % parameter
            if "select relname from pg_class" in result:
                continue
            f.write(result.strip() + ";\n\n")

    with open(file, "w") as f:
        event.listen(engine, "before_cursor_execute", callback)
        try:
            yield
        finally:
            event.remove(engine, "before_cursor_execute", callback)


def schema():
    with dumper(engine, "out/create_schema.sql"):

        with Session(engine) as session:
            session.execute(text("drop schema if exists socialmarket cascade"))
            session.execute(text("create schema socialmarket"))
            session.execute(text("set search_path to socialmarket"))
            session.commit()
        Base.metadata.create_all(engine)

    def format_name(name: str) -> str:
        return name.replace("_", "\\_")

    def col(column: Column) -> str:
        result = ""
        name = f"\\text{{{format_name(column.name)}}}"
        if column.primary_key:
            result += f"\\underline{{{name}}}"
        elif column.unique:
            result += name.replace("text", "textit")
        else:
            result += name
        if len(column.foreign_keys) > 0:
            (foreign,) = column.foreign_keys
            result += f"^\\text{{{format_name(foreign.column.table.name)}}}"
        if column.nullable:
            result += "_\\text{O}"
        return result

    md_file = open("out/schema.md", "w")
    for _, t in sorted(Base.metadata.tables.items()):
        md_file.write(
            f"$\\text{{{format_name(t.name.upper())}}}({','.join(col(column) for column in t.columns)})$"
        )
        md_file.write("\n")
