from contextlib import AbstractAsyncContextManager
from arsenic.browsers import Browser
from arsenic.services import Service
from arsenic.session import Session
from typing import Type, Any
from collections.abc import Coroutine
from types import TracebackType

class SessionContext(AbstractAsyncContextManager[Session]):
    def __aexit__(
        self,
        __exc_type: Type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
        /,
    ) -> Coroutine[Any, Any, bool | None]: ...

def get_session(
    service: Service, browser: Browser, bind: str = ...
) -> SessionContext: ...
async def start_session(
    service: Service, browser: Browser, bind: str = ...
) -> Session: ...
async def stop_session(session: Session) -> None: ...
