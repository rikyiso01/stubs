from arsenic import SessionContext
from asyncio_pool import AioPool
from httpx import AsyncClient
from MySQLdb import Connection
from pwnlib.tubes.tube import tube
from sqlalchemy.orm import Session
from sqlalchemy.engine.base import Engine


async def main():
    async with SessionContext():
        ...
    async with AioPool(5):
        ...
    async with AsyncClient():
        ...


with Connection():
    ...

with tube():
    ...

with Session(Engine("")):
    ...
