import random

def test_flaky():
    assert random.random() >= 0.5  # deliberately flaky ~50%
