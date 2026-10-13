from calc import add, mul

def test_add():
    assert add(2, 3) == 5

def test_mul():
    assert mul(3, 4) == 12


def test_sub_new():
    from calc import sub
    assert sub(5, 3) == 2
