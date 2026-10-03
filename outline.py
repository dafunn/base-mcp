"""The structure of a source file, from a real parse.

Each definition is reported with its full extent and nesting; a match inside a
string or docstring is not a definition. Grammars are imported on first use,
not at startup.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Extension -> grammar name. Two extensions can share one grammar; TSX cannot
# share TypeScript's, because the JSX ambiguity is resolved in the grammar.
SUFFIX_LANG: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".sh": "bash", ".bash": "bash",
    ".yaml": "yaml", ".yml": "yaml",
    ".md": "markdown", ".markdown": "markdown",
    ".sql": "sql",
    ".tf": "hcl", ".tfvars": "hcl", ".hcl": "hcl",
}


def _load(module: str, fn: str = "language") -> Callable[[], Any]:
    def loader() -> Any:
        mod = __import__(module)
        return getattr(mod, fn)()
    return loader


_LOADERS: dict[str, Callable[[], Any]] = {
    "python": _load("tree_sitter_python"),
    "javascript": _load("tree_sitter_javascript"),
    "typescript": _load("tree_sitter_typescript", "language_typescript"),
    "tsx": _load("tree_sitter_typescript", "language_tsx"),
    "go": _load("tree_sitter_go"),
    "rust": _load("tree_sitter_rust"),
    "java": _load("tree_sitter_java"),
    "ruby": _load("tree_sitter_ruby"),
    "bash": _load("tree_sitter_bash"),
    "yaml": _load("tree_sitter_yaml"),
    "markdown": _load("tree_sitter_markdown"),
    "sql": _load("tree_sitter_sql"),
    "hcl": _load("tree_sitter_hcl"),
}

# Node types worth a line in an outline, and the word to show for each.
_DEFS: dict[str, dict[str, str]] = {
    "python": {"function_definition": "def", "class_definition": "class"},
    "javascript": {
        "function_declaration": "function", "class_declaration": "class",
        "method_definition": "method", "generator_function_declaration": "function*",
        "lexical_declaration": "const", "variable_declaration": "var",
    },
    "typescript": {
        "function_declaration": "function", "class_declaration": "class",
        "method_definition": "method", "interface_declaration": "interface",
        "type_alias_declaration": "type", "enum_declaration": "enum",
        "lexical_declaration": "const", "variable_declaration": "var",
    },
    "go": {
        "function_declaration": "func", "method_declaration": "method",
        "type_declaration": "type",
    },
    "rust": {
        "function_item": "fn", "struct_item": "struct", "enum_item": "enum",
        "impl_item": "impl", "trait_item": "trait", "mod_item": "mod",
    },
    "java": {
        "class_declaration": "class", "interface_declaration": "interface",
        "method_declaration": "method", "enum_declaration": "enum",
        "record_declaration": "record",
    },
    "ruby": {"method": "def", "class": "class", "module": "module"},
    "bash": {"function_definition": "function"},
    "yaml": {"block_mapping_pair": "key"},
    "markdown": {"atx_heading": "#", "setext_heading": "#"},
    # DDL only.
    "sql": {
        "create_table": "table", "create_view": "view", "create_index": "index",
        "create_function": "function", "create_schema": "schema",
        "create_type": "type", "alter_table": "alter",
    },
    # HCL has one shape for everything, so the label carries the meaning and
    # the fallback name (the block's first line) is the useful text.
    "hcl": {"block": "block"},
}
_DEFS["tsx"] = _DEFS["typescript"]

def _text(node: Any, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace").strip()


def _refine_yaml(node: Any, source: bytes) -> tuple[bool, str | None]:
    """Keep a YAML pair only if it carries structure or a human label.

    Nested values are structure and stay, a `name:` value becomes the entry's
    name, and other leaf scalars go.
    """
    key = node.child_by_field_name("key")
    value = node.child_by_field_name("value")
    if key is None:
        return False, None
    key_text = _text(key, source)
    if value is not None and value.type in ("block_mapping", "block_sequence", "block_node"):
        return True, key_text
    if key_text == "name" and value is not None:
        return True, _text(value, source)[:80]
    return False, None


# A `const x = () => ...` is a definition; a `const MAX = 3` is not, so the
# value has to be function-shaped.
_FUNC_VALUE = {"arrow_function", "function_expression", "function", "class"}


def _refine_binding(node: Any, source: bytes) -> tuple[bool, str | None]:
    for child in node.named_children:
        if child.type != "variable_declarator":
            continue
        value = child.child_by_field_name("value")
        name = child.child_by_field_name("name")
        if value is not None and value.type in _FUNC_VALUE and name is not None:
            return True, _text(name, source)
    return False, None


_REFINE: dict[tuple[str, str], Any] = {
    ("yaml", "block_mapping_pair"): _refine_yaml,
}
for _lang in ("javascript", "typescript", "tsx"):
    _REFINE[(_lang, "lexical_declaration")] = _refine_binding
    _REFINE[(_lang, "variable_declaration")] = _refine_binding


_cache: dict[str, Any] = {}


@dataclass(frozen=True)
class Entry:
    name: str
    kind: str
    start_line: int  # 1-based, inclusive
    end_line: int  # 1-based, inclusive
    depth: int


def supported(suffix: str) -> bool:
    return suffix.lower() in SUFFIX_LANG


def _parser(language: str) -> Any | None:
    """A parser for `language`, or None if its grammar is not installed.

    A missing grammar is not an error: the caller falls back to a coarser
    outline.
    """
    if language in _cache:
        return _cache[language]
    try:
        from tree_sitter import Language, Parser

        parser = Parser(Language(_LOADERS[language]()))
    except Exception:  # noqa: BLE001 - absent or ABI-mismatched grammar
        parser = None
    _cache[language] = parser
    return parser


def _name_of(node: Any, source: bytes) -> str:
    """The declared name, or the node's own first line as a stand-in.

    Not every definition has a `name` field: a Rust `impl` names a type, an
    anonymous class names nothing.
    """
    for field in ("name", "type", "declarator", "key"):
        child = node.child_by_field_name(field)
        if child is not None:
            return source[child.start_byte:child.end_byte].decode("utf-8", "replace").strip()
    first = source[node.start_byte:node.end_byte].split(b"\n", 1)[0]
    return first.decode("utf-8", "replace").strip()[:80]


def outline_source(source: bytes, suffix: str, max_entries: int = 0) -> list[Entry] | None:
    """Definitions in `source`, or None if this file cannot be parsed here."""
    language = SUFFIX_LANG.get(suffix.lower())
    if language is None:
        return None
    parser = _parser(language)
    if parser is None:
        return None
    wanted = _DEFS[language]
    entries: list[Entry] = []

    def walk(node: Any, depth: int) -> None:
        if max_entries and len(entries) >= max_entries:
            return
        kind = wanted.get(node.type)
        child_depth = depth
        if kind is not None:
            refine = _REFINE.get((language, node.type))
            override = None
            if refine is not None:
                keep, override = refine(node, source)
                if not keep:
                    kind = None
        if kind is not None:
            entries.append(
                Entry(
                    name=override if override is not None else _name_of(node, source),
                    kind=kind,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    depth=depth,
                )
            )
            child_depth = depth + 1
        for child in node.children:
            walk(child, child_depth)

    walk(parser.parse(source).root_node, 0)
    if language == "markdown":
        # Headings nest under `section`, which is not an entry, so depth comes
        # from the marker instead. The marker is then stripped: the kind is
        # already "#".
        entries = [
            Entry(e.name.lstrip("#").strip(), e.kind, e.start_line, e.end_line,
                  max(len(e.name) - len(e.name.lstrip("#")) - 1, 0))
            for e in entries
        ]
    return entries
