from tech_debtor.analyzers.base import parse_python, tree_to_functions, tree_to_classes


CODE = """
def foo(x, y):
    return x + y

class Bar:
    def method(self):
        pass

def baz():
    if True:
        for i in range(10):
            pass
"""


def test_parse_python():
    tree = parse_python(CODE)
    assert tree is not None
    assert tree.root_node.type == "module"


def test_tree_to_functions():
    tree = parse_python(CODE)
    funcs = tree_to_functions(tree.root_node)
    names = [f.child_by_field_name("name").text.decode() for f in funcs]
    assert "foo" in names
    assert "baz" in names
    assert "method" in names


def test_tree_to_classes():
    tree = parse_python(CODE)
    classes = tree_to_classes(tree.root_node)
    names = [c.child_by_field_name("name").text.decode() for c in classes]
    assert names == ["Bar"]
