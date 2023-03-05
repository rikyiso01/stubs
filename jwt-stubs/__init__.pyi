from collections.abc import Iterable
from mte.json import JsonType, PythonJsonType

def encode(
    payload: PythonJsonType,
    key: str,
    algorithm: str = ...,
    headers: PythonJsonType = ...,
) -> str: ...
def decode(
    jwt: str,
    key: str,
    algorithms: Iterable[str] = ...,
) -> JsonType: ...
