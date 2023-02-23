from .schema import engine
from sqlalchemy.orm import Session
from sqlalchemy import text
from .schema import schema
from .big_data import big_data
from .physical import physical

IDS = [6, 10, 14]


def get_identation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def process_plan(plan: list[str]) -> list[str]:
    print(plan)
    result = ["```mermaid", "flowchart TD"]
    stack: list[tuple[int, int]] = []
    global_id = 0
    for row in plan:
        if "->" not in row and stack:
            result[-1] = result[-1][:-2] + "\\n" + row + '"]'
            continue
        if stack:
            while get_identation(row) <= stack[-1][1]:
                stack.pop()
            result.append(f"{stack[-1][0]}---{global_id}")
        stack.append((global_id, get_identation(row)))
        result.append(f'{global_id}["{row.lstrip(" ->")}"]')
        global_id += 1
    result.append("```")
    return result


def draw_plan() -> list[str]:
    result: list[list[str]] = []
    sources = [""]
    for id in IDS:
        with Session(engine) as session:
            session.execute(text("analyze"))
            session.commit()
        with Session(engine) as session:
            row = list(session.execute(text("explain " + sources[id])).scalars())
            result.append(process_plan(row))
    return ["\n".join(row) for row in result]


def get_times() -> list[float]:
    result: list[float] = []
    sources = [""]
    for id in IDS:
        with Session(engine) as session:
            session.execute(text("analyze"))
            session.commit()
        with Session(engine) as session:
            row = list(session.execute(text("explain analyze " + sources[id])))[-1]
            time = float(row[0].split(" ")[2])
            result.append(time)
    return result


def times() -> tuple[list[list[str]], list[str]]:
    schema()
    big_data()
    table = [
        ["1"],
        ["2"],
        ["3"],
    ]
    drawing = draw_plan()
    for i, row in enumerate(get_times()):
        table[i].append(str(row))
    physical()
    drawing.extend(draw_plan())
    for i, row in enumerate(get_times()):
        table[i].append(str(row))
    return table, drawing
