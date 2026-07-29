# tools

Maintenance scripts for the archive. Standard library only — no dependencies to install.

Two sources of truth, and everything else is generated from them:

- **`*/metadata.json`** — one per entry, the record of a reproduced exploit
- **`data/profile.json`** — the facts that appear on both the profile README and
  wolfhacking.com.ar: certifications, bug bounty figures, published advisories

Three destinations are generated and must never be edited by hand: the two indices and
the README listing in this repository, the managed blocks of the profile README, and
`site-data.js` in the website repository.

## Regular flow

After adding an entry, or every so often to pick up scores published after the fact:

```bash
python3 tools/enrich_metadata.py    # fill in missing severity / CVSS
python3 tools/gen_indices.py        # rebuild README listing + both indices
```

After editing `data/profile.json` (a new certification, updated bug bounty stats):

```bash
python3 tools/gen_profile_section.py --write ../galletitaconpate/README.md
python3 tools/gen_site_data.py --write ../wolfhacking/site-data.js
```

The `sync` workflow runs all of this and commits to both destinations, so in practice
editing the source and pushing is enough.

## Scripts

### `enrich_metadata.py`

Fills empty `severity` and `cvss` fields. Only ever writes to fields that are empty, so
a value set by hand survives every later run.

Sources are tried in order, falling back to the entry's CVE aliases when its own id is
unknown to a database (vendor ids like `ADV190005` are absent from all three):

1. **GitHub Advisories** — severity, score and vector in one response
2. **OSV** — vector only; the score is computed locally by `cvss.py`
3. **NVD** — last resort, rate limited to 5 requests / 30s without a key

It also reconciles the two fields against each other. The databases disagree with one
another, and where a score came from one and a rating from another they could land in
different bands. The CVSS severity scale is a fixed function of the score, so whenever a
score is present it decides the rating.

```bash
python3 tools/enrich_metadata.py --dry-run   # report, write nothing
python3 tools/enrich_metadata.py --offline   # derive from local data only, no API calls
python3 tools/enrich_metadata.py --force     # re-fetch entries that already have data
```

Set `GITHUB_TOKEN` to raise the GitHub rate limit from 60/h to 5000/h, and `NVD_API_KEY`
for the NVD limit. Neither is required.

Nine entries have no CVSS v3 data anywhere upstream — mostly pre-2015 CVEs scored only
under CVSS v2, which this does not compute. They render without a score.

### `gen_indices.py`

Rebuilds all three indices. Replaces the `scripts/advisory_index.sh` referenced by older
copies of the index headers, which was never committed and so could not be re-run.

- `README.md` — the product listing, spliced between `<!-- INDEX:START -->` and
  `<!-- INDEX:END -->`; the prose around the markers is left alone
- `INDEX_BY_CLASS.md` — by vulnerability class
- `INDEX_BY_CWE.md` — by weakness, with entries carrying no CWE under *Unmapped*

`--check` exits non-zero when an index is stale instead of writing, for use in CI.

### `gen_profile_section.py`

Renders three blocks of the profile README, each spliced between its own marker pair:

| Markers | Content | Source |
| :--- | :--- | :--- |
| `exploit-development` | current year in full, previous year's strongest, rest in a `<details>` | `*/metadata.json` |
| `bug-bounty` | platform stats and the published advisories table | `data/profile.json` |
| `certifications` | earned, Pro Labs, and in-progress with percentages | `data/profile.json` |

Ordering for exploits is year descending then CVSS descending, so nothing needs manual
reordering as entries are added. `--check` exits non-zero when a block is stale.

Tunables at the top of the file: `FEATURED_YEARS`, `SELECTED_YEAR`, `SELECTED_LIMIT`.

### `gen_site_data.py`

Writes `site-data.js` for the website: one `window.WH_DATA` assignment holding the exploit
counters and records, plus the certifications, bug bounty figures and advisories from
`profile.json`.

The site is static, has no build step, and its CSP forbids cross-origin requests, so it
cannot read this repository at runtime — the data is committed to it instead. A plain
script assigning a global is used rather than a JSON file and `fetch`, because it is
synchronous, works from `file://` while developing, and fails detectably.

The output is a pure function of the inputs, with **no timestamp**. A timestamp would make
the weekly sync rewrite the file every run, producing an empty commit and a pointless
deploy, and would make `--check` permanently report stale.

Tunables: `FEATURED_COUNT` (entries rendered as cards), `TOP_CLASSES`.

### `archive.py`

Loading and ordering shared by all three generators: `load_entries()`, `sort_key()`,
`entry_url()`, `class_label()`, `CLASS_LABELS`. This exists because `load_entries()` had
been copied per generator, so a fix in one left the others disagreeing.

`headline(entry)` returns the optional hand-written `headline` field, falling back to
`summary`. Upstream summaries are occasionally truncated or misspelled at the source;
`headline` overrides the display text for the entries worth polishing without discarding
what upstream actually said.

### `cvss.py`

CVSS v3.0/v3.1 base score from a vector string, per the specification's section 8.1 and
Appendix A roundup. Needed because OSV publishes vectors without scores. Tolerates the
prefixless vectors some entries were recorded with.

v4.0 vectors are detected and skipped rather than guessed: scoring them needs the
macrovector lookup tables. v2 is not implemented.

### `cwe_names.py`

CWE id to name mapping for the weakness index headings. Add an entry when a new weakness
appears; an unmapped id still renders, just without its name.

## Automation

`.github/workflows/sync-profile.yml` runs the enrich and generate steps on a weekly cron,
on pushes that touch `metadata.json`, `data/` or `tools/`, and on demand, then commits to
this repository, the profile repository and the website repository.

It is deliberately one workflow rather than one per destination: `enrich_metadata.py` calls
three external APIs and mutates the metadata, so splitting it would double that load and
let two concurrent runs push conflicting states — and the profile and the site could end up
reflecting different enrichment.

Pushing to the other two repositories needs a token the default `GITHUB_TOKEN` cannot
provide, since that one is scoped to this repository. Create **one** fine-grained PAT
covering `galletitaconpate/galletitaconpate` and `galletitaconpate/wolfhacking` with
**Contents: read and write**, and store it as the `SYNC_TOKEN` secret here
(*Settings → Secrets and variables → Actions*). Nothing else needs a stored credential.

Without the secret the workflow still enriches metadata and rebuilds the indices; the
cross-repository steps are skipped with an explanatory notice instead of failing.

Note that a PAT-authored commit **does** trigger workflows in the destination repository,
unlike one made with `GITHUB_TOKEN` — worth remembering if either destination ever gains
CI of its own.
