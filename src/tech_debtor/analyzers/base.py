from __future__ import annotations

from typing import Protocol

from tree_sitter import Language, Parser, Tree, Node
import tree_sitter_python as tspython

from tech_debtor.config import Config
from tech_debtor.models import Finding

PY_LANGUAGE = Language(tspython.language())


def parse_python(source: str) -> Tree:
    parser = Parser(PY_LANGUAGE)
    return parser.parse(bytes(source, "utf-8"))


def _find_nodes(node: Node, target_type: str) -> list[Node]:
    results = []
    if node.type == target_type:
        results.append(node)
    for child in node.children:
        results.extend(_find_nodes(child, target_type))
    return results


def tree_to_functions(root: Node) -> list[Node]:
    return _find_nodes(root, "function_definition")


def tree_to_classes(root: Node) -> list[Node]:
    return _find_nodes(root, "class_definition")


class Analyzer(Protocol):
    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]: ...
