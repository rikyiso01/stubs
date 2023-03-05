from mte.json import PythonJsonType, JsonType
from mte.yaml import PythonYamlType, YamlType
from mte.toml import TomlType


a: PythonJsonType = {"1": {"1": [1, 2, 3, True], 2: (1, 2, 3)}}
b: JsonType = {"1": {"1": [1, 2, 3, True], "2": [1, 2, 3]}}
c: PythonYamlType = {"1": {1, 2, 3}, True: [1, 2, 3], None: (1, 2, 3)}
d: YamlType = {"1": {1, 2, 3}, "True": [1, 2, 3]}
e: TomlType = {"1": {"1": [1, 2, 3, True], "2": [1, 2, 3]}}
