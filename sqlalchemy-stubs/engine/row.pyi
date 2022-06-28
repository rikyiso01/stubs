from typing import Any

class Row:
    def __getattr__(self, attr: str) -> Any: ...
