from arsenic.browsers import Browser
from arsenic.services import Service
from arsenic.session import Session
from typing import Type
from types import TracebackType
from mte.protocols import AsyncContextManager

class SessionContext(AsyncContextManager[Session]):
    async def __aenter__(self) -> Session: ...
    async def __aexit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
        /,
    ) -> bool | None: ...

def get_session(
    service: Service, browser: Browser, bind: str = ...
) -> SessionContext: ...
async def start_session(
    service: Service, browser: Browser, bind: str = ...
) -> Session: ...
async def stop_session(session: Session) -> None: ...
