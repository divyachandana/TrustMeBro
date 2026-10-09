from trustmebro import scanner

VULNERABLE = '''
def orders(db, customer):
    return db.execute(f"SELECT * FROM orders WHERE customer = '{customer}'").fetchall()
'''

SAFE = '''
def orders(db, customer):
    return db.execute("SELECT * FROM orders WHERE customer = ?", (customer,)).fetchall()
'''


def test_base_rule_flags_fstring_query():
    assert scanner.scan_code(VULNERABLE, include_learned=False)


def test_base_rule_allows_parameterized_query():
    assert not scanner.scan_code(SAFE, include_learned=False)
