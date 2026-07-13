"""Put services/feed-sync on sys.path so tests import its modules directly."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
