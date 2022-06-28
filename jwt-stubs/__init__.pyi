from collections.abc import Iterable

_JsonBaseType = str | int | float | bool | None

_JsonEncodeObject = dict[_JsonBaseType, _JsonEncode]
_JsonEncode = (
    _JsonBaseType | list[_JsonEncode] | _JsonEncodeObject | tuple[_JsonEncode, ...]
)

_JsonDecodeObject = dict[_JsonBaseType, _JsonDecode]
_JsonDecode = _JsonBaseType | list[_JsonDecode] | _JsonDecodeObject

def encode(
    payload: _JsonEncodeObject,
    key: str,
    algorithm: str = ...,
    headers: _JsonEncode = ...,
) -> str: ...
def decode(
    jwt: str,
    key: str,
    algorithms: Iterable[str] = ...,
) -> _JsonDecodeObject: ...
