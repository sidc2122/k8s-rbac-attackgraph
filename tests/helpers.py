"""Shared helpers for the test suite."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


def sample(name):
    return os.path.join(SAMPLES, name)
