from arsenic import SessionContext
from asyncio_pool import AioPool
from pwnlib.tubes.tube import tube
from sqlalchemy.orm import Session
from sqlalchemy.engine.base import Engine


async def main():
    async with SessionContext():
        ...
    async with AioPool(5):
        ...


with tube():
    ...

with Session(Engine("")):
    ...
