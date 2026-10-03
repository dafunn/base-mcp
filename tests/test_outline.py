"""The parsed outline: extent, nesting, and code versus text that merely looks
like code."""
from __future__ import annotations

import outline


def test_a_definition_names_its_whole_extent():
    src = b"class Widget:\n    def render(self, x):\n        return x\n\ndef main():\n    pass\n"
    entries = outline.outline_source(src, ".py")
    by_name = {e.name: e for e in entries}
    assert (by_name["render"].start_line, by_name["render"].end_line) == (2, 3)
    assert (by_name["Widget"].start_line, by_name["Widget"].end_line) == (1, 3)
    assert (by_name["main"].start_line, by_name["main"].end_line) == (5, 6)


def test_nesting_is_reported():
    src = b"class Widget:\n    def render(self):\n        pass\n"
    depths = {e.name: e.depth for e in outline.outline_source(src, ".py")}
    assert depths == {"Widget": 0, "render": 1}


def test_a_definition_inside_a_string_is_not_a_definition():
    """A definition inside a string is text, not code."""
    src = b'DOC = """\ndef not_a_function():\n    pass\n"""\n\ndef real():\n    pass\n'
    names = [e.name for e in outline.outline_source(src, ".py")]
    assert names == ["real"]


def test_unsupported_and_unparsable_return_none_rather_than_raising():
    """A missing grammar must not fail the read - the caller falls back."""
    assert outline.outline_source(b"x = 1", ".zzz") is None
    assert outline.supported(".py") and not outline.supported(".zzz")


def test_several_languages_are_recognised():
    for suffix, src, want in [
        (".go", b"func Handler(w int) {\n}\n", "Handler"),
        (".rs", b"pub fn handler(x: u32) {\n}\n", "handler"),
        (".rb", b"def handler(x)\nend\n", "handler"),
        (".ts", b"export interface Widget {\n  a: string;\n}\n", "Widget"),
        (".sh", b"deploy() {\n  echo hi\n}\n", "deploy"),
    ]:
        entries = outline.outline_source(src, suffix)
        assert entries, suffix
        assert any(want in e.name for e in entries), (suffix, [e.name for e in entries])


def test_every_supported_extension_is_parseable():
    for suffix in (".py", ".pyi", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".go",
                   ".rs", ".java", ".rb", ".sh", ".bash", ".md", ".yaml",
                   ".yml", ".sql", ".tf"):
        assert outline.supported(suffix), suffix


def test_rust_reports_nesting_and_extent():
    src = b"pub struct Widget { a: u32 }\nimpl Widget {\n    pub fn render(&self) {}\n}\n"
    got = [(e.kind, e.name, e.start_line, e.end_line, e.depth)
           for e in outline.outline_source(src, ".rs")]
    assert ("struct", "Widget", 1, 1, 0) in got
    assert ("impl", "Widget", 2, 4, 0) in got
    assert ("fn", "render", 3, 3, 1) in got


def test_markdown_depth_follows_the_heading_level():
    """`section` nests headings but is not itself an entry, so the level comes
    from the marker the author wrote."""
    src = b"# Title\n\n## Section\n\n### Deep\n"
    depths = {e.name: e.depth for e in outline.outline_source(src, ".md")}
    # The marker sets the depth and is then stripped: the kind is already "#",
    # so keeping it would render "# # Title".
    assert depths == {"Title": 0, "Section": 1, "Deep": 2}


def test_sql_maps_ddl_not_queries():
    """A file of SELECTs has no structure worth mapping; a schema does."""
    src = b"CREATE TABLE users (id int);\nSELECT * FROM users;\nCREATE VIEW active AS SELECT 1;\n"
    kinds = [e.kind for e in outline.outline_source(src, ".sql")]
    assert kinds == ["table", "view"]


def test_hcl_blocks_carry_their_labels():
    """Everything in HCL is a block, so the label is what distinguishes them."""
    src = b'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\nvariable "v" {}\n'
    names = [e.name for e in outline.outline_source(src, ".tf")]
    assert any("aws_s3_bucket" in n for n in names)
    assert any("variable" in n for n in names)


def test_an_ansible_playbook_outlines_by_play_and_task_name():
    """A playbook is YAML: the label lives in the `name:` value, and leaf
    scalars are noise."""
    play = (
        b"---\n"
        b"- name: Configure webservers\n"
        b"  hosts: web\n"
        b"  become: true\n"
        b"  tasks:\n"
        b"    - name: Install nginx\n"
        b"      ansible.builtin.apt:\n"
        b"        name: nginx\n"
    )
    entries = outline.outline_source(play, ".yml")
    names = [e.name for e in entries]
    assert "Configure webservers" in names
    assert "Install nginx" in names
    assert "tasks" in names
    # Leaf scalars are dropped; the key names themselves are not the structure.
    assert "hosts" not in names and "become" not in names
    # tasks nests under the play.
    depth = {e.name: e.depth for e in entries}
    assert depth["Install nginx"] > depth["Configure webservers"]


def test_a_function_valued_const_is_a_definition_but_a_plain_one_is_not():
    src = b"export const App = () => 1;\nconst MAX = 3;\nexport function Page() { return 1; }\n"
    names = [e.name for e in outline.outline_source(src, ".tsx")]
    assert names == ["App", "Page"]


def test_typescript_covers_its_whole_vocabulary():
    src = (b"export interface Widget { a: string }\nexport type Id = string;\n"
           b"export class Thing {\n  render(x: number): void {}\n}\n"
           b"export enum Colour { Red }\n")
    got = {(e.kind, e.name) for e in outline.outline_source(src, ".ts")}
    assert {("interface", "Widget"), ("type", "Id"), ("class", "Thing"),
            ("method", "render"), ("enum", "Colour")} <= got
