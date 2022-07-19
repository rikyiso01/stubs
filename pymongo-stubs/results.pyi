from typing import Any

class InsertOneResult:
    inserted_id: Any

class InsertManyResult:
    inserted_ids: list[Any]
