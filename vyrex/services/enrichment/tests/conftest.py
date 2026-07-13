"""Put services/enrichment on sys.path so tests can import the modules directly."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
