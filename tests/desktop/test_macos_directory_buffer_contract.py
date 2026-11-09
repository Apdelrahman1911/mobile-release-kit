"""Keep every first-party directory caller compatible with the fixed native ABI."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def integer(expression):
    node = ast.parse(expression.strip(), mode="eval").body
    def value(n):
        if isinstance(n, ast.Constant) and type(n.value) is int:
            return n.value
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mult)):
            return value(n.left) + value(n.right) if isinstance(n.op, ast.Add) else value(n.left) * value(n.right)
        raise ValueError("Unreviewed directory buffer expression: " + expression)
    return value(node)


def directory_callers(root):
    rows = []
    for path in sorted(root.rglob("*.rs")):
        source = path.read_text()
        for call in re.finditer(r"(?<!fn )directory_block\(", source):
            argument = re.search(r"&mut\s+([A-Za-z_]+)", source[call.start():call.start()+260])
            if argument is None:
                raise ValueError("Unresolved directory argument: " + str(path))
            name = argument[1]
            declarations = list(re.finditer(
                r"let\s+mut\s+" + re.escape(name) + r"\s*=\s*(?:vec!\s*)?\[\s*0(?:_?u8)?\s*;\s*([^\]]+)\]",
                source[:call.start()]))
            if not declarations:
                raise ValueError("Unresolved directory allocation: " + str(path))
            size = declarations[-1][1].strip()
            if re.fullmatch(r"[A-Z_]+", size):
                constant = re.search(r"const\s+" + size + r"\s*:\s*usize\s*=\s*([^;]+);", source)
                if constant is None:
                    raise ValueError("Unresolved directory size: " + str(path))
                size = constant[1]
            rows.append((str(path.relative_to(root)), source.count("\n", 0, call.start()) + 1, integer(size)))
    return rows


class DirectoryBufferContract(unittest.TestCase):
    def test_all_actual_callers_match_native_fixed_size(self):
        native = (ROOT / "desktop/native/macos-installed-native/src/lib.rs").read_text()
        contract = re.search(r"fn directory_block\([^\{]+\{\s*if buffer.len\(\) != (\d+)", native)
        self.assertIsNotNone(contract)
        required = int(contract[1])
        self.assertEqual(required, 65536)
        rows = directory_callers(ROOT)
        self.assertGreaterEqual(len(rows), 31)
        self.assertEqual([(p, n, size) for p, n, size in rows if size != required], [])



if __name__ == "__main__":
    unittest.main()
