"""Put services/investigation-orchestrator on sys.path so tests can `import orchestrator...`.

Matches the conftest every other service already had. Its absence meant these tests only
ever passed when pytest was invoked from inside the service directory (or inside the
container, where /app is the working directory) — and failed with
`ModuleNotFoundError: No module named 'orchestrator'` when CI ran them from the repo root,
which is how CI runs them.

That failure was masked for a while: before the orchestrator requirements were added to the
CI job, these modules failed at collection on `No module named 'langgraph'` instead, so
fixing the dependency simply moved the error one step along. Between the two, the
orchestrator suite had never actually executed in CI.

`parents[1]` is services/investigation-orchestrator/, which is what makes the package name
`orchestrator` resolve. Note the package is deliberately NOT called `app`: services/api
already owns that top-level name, and two `app` packages make the suites uncollectable in a
single pytest run.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
