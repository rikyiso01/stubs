from contextlib import AbstractAsyncContextManager
from .browsers import Browser
from .services import Service
from .session import Session

class SessionContext(AbstractAsyncContextManager[Session]): ...

def get_session(
    service: Service, browser: Browser, bind: str = ...
) -> SessionContext: ...
async def start_session(
    service: Service, browser: Browser, bind: str = ...
) -> Session: ...
async def stop_session(session: Session) -> None: ...
