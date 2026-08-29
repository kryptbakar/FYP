# Thesis / demo figures

Captures the console figure set from whatever the stack is actually serving.

**Why a script and not screenshots taken by hand.** Hand-captured figures drift: a
different window width changes how many bento columns appear, a stale container build
shows last week's UI, a half-loaded panel gets caught mid-skeleton, and nothing records
which commit a figure came from. Here every figure is captured at a fixed 1600×1000
viewport at `deviceScaleFactor: 2`, so a figure in the write-up can always be regenerated
from the commit it was taken at — and if the regenerated version differs, that is a real
change in the product, not a screenshot artefact.

## Run it

```bash
# stack up first: docker compose ... --profile agentic up -d
mkdir -p dist/figures
docker run --rm --add-host=host.docker.internal:host-gateway \
  -e NODE_PATH=/usr/src/app/node_modules \
  -v "$PWD/tools/figures:/s" -v "$PWD/dist/figures:/out" -w /usr/src/app \
  zenika/alpine-chrome:with-puppeteer node /s/capture.js
```

Roughly 90 seconds for ten figures. Exit 1 if any figure was skipped, so a missing panel
fails loudly rather than leaving a gap in the set.

## Output

`dist/figures/` — **gitignored**, matching the existing convention for build output.
The images are ~4.7 MB and regenerate on demand, so they are not committed.

| Figure | What it is for |
|---|---|
| `01-overview` | The hero: live stats, tool widgets, and the pipeline constellation |
| `02-live-pipeline` | The constellation alone — cropped, so it reproduces in print |
| `03-triage-queue` | Ranked decision queue |
| `04-investigations` | Run list + execution graph in context |
| `05-execution-graph` | The graph alone: five parallel specialists, one model call |
| `06-sensors-and-fusion` | The real pipeline and the integrated-tool grid |
| `07-compliance` | CIS posture + the hash-chained evidence badge |
| `08-cases` | Incidents with the signed audit timeline |
| `09-autonomous-defense` | The Sentinel/Decoy/Mend/Forge command centre |
| `10-model-card` | The honesty screen — composite weights, `analyst labels 0`, stated limitations |

## One trade-off to be deliberate about

The figures always reflect **current** state, which is right for a live demo and wrong for
a submitted document: re-running after the corpus changes will silently make the figures
disagree with numbers quoted in your text. When a chapter is finalised, copy the figures
you cite into the thesis source and stop regenerating those.

## Two traps already handled here

1. **The vault overlay.** The cinematic unlock screen sits *above* the booted app for
   10–20 s. Element queries succeed underneath it, so a naive run produces ten identical
   screenshots of the vault. The script waits for `#vault` to hide.
2. **Capturing the previous view.** `#view` still holds the old route's content at
   navigation time, and it has no skeleton and stable text — so "wait until it looks
   loaded" passes instantly on the wrong page. The script tags the current view and waits
   for that tag to detach. The route smoke test hit exactly this and reported every result
   one route late.
