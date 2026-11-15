import ast
from pathlib import Path
from decimal import Decimal


def read_assignments(filename):
    tree = ast.parse(Path(filename).read_text())
    result = {}

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        result[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass

    return result


bitcoin = read_assignments("electrum/bitcoin.py")
util = read_assignments("electrum/util.py")

COIN = bitcoin["COIN"]

assert COIN == 10_000_000
assert util["DECIMAL_POINT_DEFAULT"] == 7
assert util["base_units"] == {
    "LCC": 7,
    "mLCC": 4,
    "uLCC": 1,
    "sat": 0,
}
assert bitcoin["TOTAL_COIN_SUPPLY_LIMIT_IN_BTC"] == 840_000_000

MAX_MONEY = bitcoin["TOTAL_COIN_SUPPLY_LIMIT_IN_BTC"] * COIN
assert MAX_MONEY == 8_400_000_000_000_000

samples = [
    ("1", 10_000_000),
    ("0.0000001", 1),
    ("0.0000002", 2),
    ("12.3456789", 123_456_789),
]

for amount, expected in samples:
    units = Decimal(amount) * COIN

    assert units == expected
    assert Decimal(expected) / COIN == Decimal(amount)

    print(f"OK: {amount} LCC = {expected} units")

print("LCC AMOUNT TESTS OK")
