from contextlib import AbstractAsyncContextManager
from asyncio import AbstractEventLoop, Future, Semaphore
from collections.abc import Awaitable, Callable, Iterable, Coroutine
from types import TracebackType
from typing import Any, TypeVar, overload, Type

_T = TypeVar("_T")
_V = TypeVar("_V")
_K = TypeVar("_K")
_J = TypeVar("_J")
_Callback = (
    Callable[[_T], Any]
    | Callable[[_T, tuple[Exception, TracebackType]], Any]
    | Callable[[_T, tuple[Exception, TracebackType], _V], Any]
)

class AioPool(AbstractAsyncContextManager[AioPool]):
    def __init__(self, size: int = ..., *, loop: AbstractEventLoop = ...) -> None: ...

    loop: AbstractEventLoop
    size: int
    semaphore: Semaphore
    n_active: int
    is_empty: bool
    is_full: bool

    async def spawn(
        self, coro: Awaitable[_T], cb: _Callback[_T, _V] = ..., ctx: _V = ...
    ) -> Future[_T]: ...
    def spawn_n(
        self, coro: Awaitable[_T], cb: _Callback[_T, _V] = ..., ctx: _V = ...
    ) -> Future[_T]: ...
    exec = spawn
    def map_n(
        self,
        fn: Callable[[_K], Awaitable[_T]],
        iterable: Iterable[_K],
        cb: _Callback[_T, _V] = ...,
        ctx: _V = ...,
    ) -> list[Future[_T]]: ...
    @overload
    async def map(
        self,
        fn: Callable[[_K], Awaitable[_T]],
        iterable: Iterable[_K],
        cb: _Callback[_T, _V] = ...,
        ctx: _V = ...,
    ) -> list[_T]: ...
    @overload
    async def map(
        self,
        fn: Callable[[_K], Awaitable[_T]],
        iterable: Iterable[_K],
        cb: _Callback[_T, _V] = ...,
        ctx: _V = ...,
        *,
        get_result: Callable[[Future[_T]], _J],
    ) -> list[_J]: ...
    async def cancel(
        self, *futures: Future[Any], get_result: Callable[[Any], Any] = ...
    ) -> tuple[list[Future[Any]], list[Any]]: ...
    def __len__(self) -> int: ...
    async def join(self) -> bool: ...
    def __aexit__(
        self,
        __exc_type: Type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
        /,
    ) -> Coroutine[Any, Any, bool | None]: ...
