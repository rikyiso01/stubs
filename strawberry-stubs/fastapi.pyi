from fastapi import APIRouter
from strawberry import Schema

class GraphQLRouter(APIRouter):
    def __init__(self, schema: Schema) -> None: ...
