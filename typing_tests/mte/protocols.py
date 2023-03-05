from mte.protocols import ContextManager, AsyncContextManager
from types import TracebackType
from contextlib import AbstractAsyncContextManager as AACM
from sys import stdin, stdout
from typing import TextIO
from mte.protocols import SupportsRichComparison

a: list[SupportsRichComparison] = []
sorted(a)


class Test(AACM["Test"]):
    async def __aexit__(
        self,
        __exc_type: type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
    ) -> bool | None:
        ...


t: ContextManager[TextIO] = stdin
t: ContextManager[TextIO] = stdout
u: AsyncContextManager[Test] = Test()
