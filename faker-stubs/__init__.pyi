from typing import Any
from faker.providers import BaseProvider
from collections.abc import Callable
from faker.proxy import UniqueProxy

class Faker:
    unique: UniqueProxy
    def __init__(self, locale: str = ..., use_weighting: bool = ...) -> None: ...
    def add_provider(self, provider: Callable[[], BaseProvider]) -> None: ...
    def __getattr__(self, attr: str) -> Callable[..., Any]: ...
