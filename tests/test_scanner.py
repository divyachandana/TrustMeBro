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


ONE_BUG = '''
def invoices(db, invoice_id):
    query = "SELECT * FROM invoices WHERE id = %s" % invoice_id
    rows = db.execute(query).fetchall()
    return rows
'''


def test_hook_ignores_existing_bugs_but_catches_identical_new_ones(tmp_path):
    from trustmebro import hook

    path = tmp_path / "app.py"
    path.write_text(ONE_BUG)
    assert not hook.new_findings(ONE_BUG + "\n# a comment\n", str(path))
    assert hook.new_findings(ONE_BUG + ONE_BUG.replace("invoices(", "reports("), str(path))
