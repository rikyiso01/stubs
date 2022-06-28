from typing import TypedDict
from starlette.requests import Request
from starlette.background import BackgroundTasks
from starlette.responses import Response

class _Context(TypedDict):
    request: Request
    background_tasks: BackgroundTasks
    response: Response

class Info:
    context: _Context
