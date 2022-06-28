from fastapi import APIRouter
from . import Schema

class GraphQLRouter(APIRouter):
    def __init__(self, schema: Schema) -> None: ...
