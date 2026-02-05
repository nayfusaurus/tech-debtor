from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class Config:
    max_complexity: int = 15
    max_cognitive_complexity: int = 10
    max_function_length: int = 50
    max_parameters: int = 5
    max_nesting_depth: int = 4
    min_severity: str = "medium"
    exclude: list[str] = field(default_factory=list)
    cost_per_line: float = 0.5


def load_config(project_path: Path) -> Config:
    pyproject = project_path / "pyproject.toml"
    if not pyproject.exists():
        return Config()

    if tomllib is None:
        return Config()

    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    tool_config = data.get("tool", {}).get("tech-debtor", {})
    if not tool_config:
        return Config()

    field_map = {
        "max-complexity": "max_complexity",
        "max-cognitive-complexity": "max_cognitive_complexity",
        "max-function-length": "max_function_length",
        "max-parameters": "max_parameters",
        "max-nesting-depth": "max_nesting_depth",
        "min-severity": "min_severity",
        "exclude": "exclude",
        "cost-per-line": "cost_per_line",
    }

    kwargs = {}
    for toml_key, attr_name in field_map.items():
        if toml_key in tool_config:
            kwargs[attr_name] = tool_config[toml_key]

    return Config(**kwargs)
