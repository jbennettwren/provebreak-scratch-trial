import time

def test_slow():
    time.sleep(100)
    assert False, "slow and red"
