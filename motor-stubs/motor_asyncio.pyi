from collections.abc import Mapping, AsyncIterable, Iterable
from typing import Any
from pymongo.results import InsertManyResult, InsertOneResult

class AsyncIOMotorClient:
    def __init__(self, uri: str) -> None: ...
    def __getitem__(self, item: str) -> AsyncIOMotorDatabase: ...

class AsyncIOMotorDatabase:
    def __getitem__(self, item: str) -> AsyncIOMotorCollection: ...

class AsyncIOMotorCollection:
    def __getitem__(self, item: str) -> AsyncIOMotorCollection: ...
    async def insert_one(self, document: Mapping[str, Any]) -> InsertOneResult: ...
    async def insert_many(
        self, documents: Iterable[Mapping[str, Any]]
    ) -> InsertManyResult: ...
    def find(
        self,
        filter: Mapping[str, Any] | None = ...,
        projection: Iterable[str] | None = ...,
    ) -> AsyncIOMotorCursor: ...
    async def find_one(
        self,
        filter: Mapping[str, Any] | None = ...,
        projection: Iterable[str] | None = ...,
    ) -> dict[str, Any]: ...
    async def count_documents(self, filter: Mapping[str, Any]) -> int: ...

class AsyncIOMotorCursor(AsyncIterable[dict[str, Any]]): ...
