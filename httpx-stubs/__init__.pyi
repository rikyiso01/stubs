from contextlib import AbstractAsyncContextManager
from types import TracebackType

_JsonType = dict[str, _JsonType] | list[_JsonType] | int | str | float | None | bool

class HTTPError(Exception): ...
class RequestError(HTTPError): ...
class TransportError(RequestError): ...
class NetworkError(TransportError): ...
class ConnectError(NetworkError): ...

class Response:
    @property
    def text(self) -> str: ...
    @property
    def content(self) -> bytes: ...
    def json(self) -> _JsonType: ...
    @property
    def status_code(self) -> int: ...

class AsyncClient(AbstractAsyncContextManager[AsyncClient]):
    async def get(
        self,
        url: str,
        *,
        data: dict[str, str] = ...,
        json: _JsonType = ...,
        auth: tuple[str, str] | None = ...,
        params: dict[str, str] = ...
    ) -> Response: ...
    async def post(
        self,
        url: str,
        *,
        data: dict[str, str] = ...,
        json: _JsonType = ...,
        auth: tuple[str, str] | None = ...,
        params: dict[str, str] = ...
    ) -> Response: ...
    def __aexit__(
        self,
        __exc_type: type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
    ) -> bool | None: ...

def get(
    url: str,
    *,
    data: dict[str, str] = ...,
    json: _JsonType = ...,
    auth: tuple[str, str] | None = ...
) -> Response: ...
def post(
    url: str,
    *,
    data: dict[str, str] = ...,
    json: _JsonType = ...,
    auth: tuple[str, str] | None = ...
) -> Response: ...
