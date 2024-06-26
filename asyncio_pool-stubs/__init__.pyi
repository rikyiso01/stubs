from asyncio import AbstractEventLoop, Future, Semaphore
from collections.abc import Awaitable, Callable, Iterable
from types import TracebackType
from typing import Any, overload, Type
from mte.protocols import AsyncContextManager

type _Callback[T, V] = (
    Callable[[T], Any]
    | Callable[[T, tuple[Exception, TracebackType]], Any]
    | Callable[[T, tuple[Exception, TracebackType], V], Any]
)

class AioPool(AsyncContextManager[AioPool]):
    def __init__(self, size: int = ..., *, loop: AbstractEventLoop = ...) -> None: ...

    loop: AbstractEventLoop
    size: int
    semaphore: Semaphore
    n_active: int
    is_empty: bool
    is_full: bool

    async def spawn[
        T, V
    ](self, coro: Awaitable[T], cb: _Callback[T, V] = ..., ctx: V = ...) -> Future[
        T
    ]: ...
    def spawn_n[
        T, V
    ](self, coro: Awaitable[T], cb: _Callback[T, V] = ..., ctx: V = ...) -> Future[
        T
    ]: ...
    exec = spawn
    def map_n[
        K, T, V
    ](
        self,
        fn: Callable[[K], Awaitable[T]],
        iterable: Iterable[K],
        cb: _Callback[T, V] = ...,
        ctx: V = ...,
    ) -> list[Future[T]]: ...
    @overload
    async def map[
        K, T, V
    ](
        self,
        fn: Callable[[K], Awaitable[T]],
        iterable: Iterable[K],
        cb: _Callback[T, V] = ...,
        ctx: V = ...,
    ) -> list[T]: ...
    @overload
    async def map[
        K, T, V, T2
    ](
        self,
        fn: Callable[[K], Awaitable[T]],
        iterable: Iterable[K],
        cb: _Callback[T, V] = ...,
        ctx: V = ...,
        *,
        get_result: Callable[[Future[T]], T2],
    ) -> list[T2]: ...
    async def cancel(
        self, *futures: Future[Any], get_result: Callable[[Any], Any] = ...
    ) -> tuple[list[Future[Any]], list[Any]]: ...
    def __len__(self) -> int: ...
    async def join(self) -> bool: ...
    async def __aenter__(self) -> AioPool: ...
    async def __aexit__(
        self,
        __exc_type: Type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
        /,
    ) -> bool | None: ...
