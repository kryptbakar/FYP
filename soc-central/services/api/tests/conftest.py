"""Put services/api on sys.path so tests can `import app...` without installing."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
