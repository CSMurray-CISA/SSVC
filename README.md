# Multi-Vendor SSVC Scoring Dashboard

This keeps the existing Microsoft CVRF upload workflow and adds automatically refreshed advisory views for Oracle, Adobe, Apple, Cisco, Fortinet, MediaTek, Mozilla, Qualcomm, and SolarWinds.

The **Exploited** view cross-references parsed vendor CVEs with CISA's Known Exploited Vulnerabilities catalog. It shows the vendor's available CVSS/SSVC metrics together with the KEV date, remediation deadline, required action, ransomware-use field, and notes. Microsoft CVEs marked active in an uploaded CVRF file are also added while that browser session is open.

## Add it to the existing GitHub Pages repository

Copy these items into the repository root:

- `index.html`
- `scripts/update_oracle.py`
- `scripts/update_vendors.py`
- `requirements.txt`
- `.github/workflows/refresh-oracle.yml`
- `oracle-data/releases.json`
- the complete `vendor-data/` directory

Do not omit `vendor-data/`: its tracked manifests prevent the vendor tabs from returning 404 before their first refresh.

In GitHub, open **Actions → Refresh vendor security data → Run workflow** once. The workflow runs Oracle plus a separate matrix job for Adobe, Apple, Cisco, Fortinet, MediaTek, Mozilla, Qualcomm, and SolarWinds. Each successful job uploads only that vendor's advisory files. A final publish job merges the successful results, cross-references CISA KEV, builds the Exploited view, and commits everything in one push.

One blocked or changed vendor site no longer stops the others. Its last successful data stays in place, while the other jobs continue refreshing. The workflow runs daily, so new releases appear without editing the site.

The workflow keeps the 12 newest discovered CPU/CSPU releases. Change `MAX_RELEASES` in `scripts/update_oracle.py` if you want a different history depth.

## Local preview

After running the refresh script, serve the folder through HTTP (opening `index.html` directly cannot load the JSON files):

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## Scoring behavior

Vendor CVSS vectors feed the same Impact, Automatable, Severity, and Internet Exposed derivations already used by the Microsoft view. Where a vendor does not publish a CVSS score or vector (notably many Apple and Mozilla entries), the affected fields remain `Unknown` instead of being guessed. CISA KEV matches are labeled `active`.

ARM and Broadcom VC are intentionally not included. ARM's filtered Product Security Center depends on a private client-side search service, and the supplied Broadcom VC portal currently returns an access-denied page. Keeping them out prevents silent or stale results.
