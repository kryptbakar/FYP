# Self-hosted fonts (optional, air-gap-clean)

The console uses the brief's type system — **Inter** / **IBM Plex Sans** for UI and
**IBM Plex Mono** for technical tokens — declared with `@font-face` in `../app.css`. Until
the font files are present it falls back to the **system stack**, and **nothing is fetched
at runtime** (a missing file simply falls through; there are no external/CDN references).

To activate the real fonts, drop these `.woff2` files here (filenames must match the
`@font-face src` in `app.css`):

```
assets/fonts/
  Inter.woff2          # Inter (variable or 400/500)
  IBMPlexSans.woff2    # IBM Plex Sans
  IBMPlexMono.woff2    # IBM Plex Mono
```

All three are **OFL-licensed**. Obtain them on a connected/staging machine (they are not
fetched by this repo to keep the build air-gap-clean), e.g.:

```bash
# on a machine WITH internet, then copy the files here + commit:
#   Inter:      https://github.com/rsms/inter/releases  (Inter.var.woff2 -> Inter.woff2)
#   IBM Plex:   https://github.com/IBM/plex/releases
```

No code changes are needed — the `@font-face` rules already point at these paths, and the
UI picks them up on next load. Add the OFL license text alongside the files for attribution.
