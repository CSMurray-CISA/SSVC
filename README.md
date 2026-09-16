# Microsoft & Oracle SSVC Scoring Dashboard

This keeps the existing Microsoft CVRF upload workflow and adds an Oracle tab backed by Oracle's official CSAF JSON advisories.

## Add it to the existing GitHub Pages repository

Copy these items into the repository root:

- `index.html`
- `scripts/update_oracle.py`
- `.github/workflows/refresh-oracle.yml`
- `oracle-data/releases.json`

In GitHub, open **Actions → Refresh Oracle security data → Run workflow** once. The workflow discovers the newest Oracle CPU and CSPU advisory pages, downloads their official CSAF files, and commits the same-origin files used by the Oracle release dropdown. It also runs daily, so a new Oracle release appears without editing the site.

The workflow keeps the 12 newest discovered CPU/CSPU releases. Change `MAX_RELEASES` in `scripts/update_oracle.py` if you want a different history depth.

## Local preview

After running the refresh script, serve the folder through HTTP (opening `index.html` directly cannot load the JSON files):

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## Scoring behavior

Oracle CVSS vectors feed the same Impact, Automatable, Severity, and Internet Exposed derivations already used by the Microsoft view. Oracle's CSAF does not assert public exploitation status, so Oracle rows remain `none` unless a separate enrichment source is added later. CSAF entries marked only `known_not_affected` are excluded.
