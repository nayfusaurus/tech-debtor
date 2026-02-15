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

    # Exception handling configuration
    allow_bare_except: bool = False
    allow_broad_except: bool = False
    check_resource_leaks: bool = True
    check_divide_by_zero: bool = True
    check_float_comparison: bool = True
    check_object_comparison: bool = True
    check_uncaught_exceptions: bool = False  # Opt-in (noisy)
    check_unchecked_returns: bool = False    # Opt-in (very noisy)

    # Security configuration
    check_hardcoded_credentials: bool = True
    check_unsafe_deserialization: bool = True
    check_command_injection: bool = True
    check_sql_injection: bool = True


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
        "allow-bare-except": "allow_bare_except",
        "allow-broad-except": "allow_broad_except",
        "check-resource-leaks": "check_resource_leaks",
        "check-divide-by-zero": "check_divide_by_zero",
        "check-float-comparison": "check_float_comparison",
        "check-object-comparison": "check_object_comparison",
        "check-uncaught-exceptions": "check_uncaught_exceptions",
        "check-unchecked-returns": "check_unchecked_returns",
        "check-hardcoded-credentials": "check_hardcoded_credentials",
        "check-unsafe-deserialization": "check_unsafe_deserialization",
        "check-command-injection": "check_command_injection",
        "check-sql-injection": "check_sql_injection",
    }

    kwargs = {}
    for toml_key, attr_name in field_map.items():
        if toml_key in tool_config:
            kwargs[attr_name] = tool_config[toml_key]

    return Config(**kwargs)
