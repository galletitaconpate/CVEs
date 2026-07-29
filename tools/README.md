# tools

Maintenance scripts for the archive. Standard library only — no dependencies to install.

Everything here derives from the `metadata.json` files, which are the single source of
truth. The indices and the profile section are generated artifacts: edit metadata, then
regenerate.

## Regular flow

After adding an entry, or every so often to pick up scores published after the fact:

```bash
python3 tools/enrich_metadata.py    # fill in missing severity / CVSS
python3 tools/gen_indices.py        # rebuild README listing + both indices
```

The profile README is updated by the `sync-profile` workflow, or by hand:

```bash
python3 tools/gen_profile_section.py --write ../galletitaconpate/README.md
```

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

Renders the `exploit development` section of the profile README: the current advisory year
in full, the previous year's strongest entries, and the rest folded into a `<details>`.
Ordering is year descending then CVSS descending, so nothing needs manual reordering as
entries are added.

`--write <README>` splices it between `<!-- exploit-development:start -->` and
`<!-- exploit-development:end -->`. With no `--write` it prints to stdout.

Tunables at the top of the file: `FEATURED_YEARS`, `SELECTED_YEAR`, `SELECTED_LIMIT`.

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
on pushes that touch `metadata.json` or `tools/`, and on demand, then commits to both
repositories.

Pushing to the profile repository needs a token the default `GITHUB_TOKEN` cannot provide,
since that one is scoped to this repository. Create a fine-grained PAT limited to the
`galletitaconpate/galletitaconpate` repository with **Contents: read and write**, and store
it as the `PROFILE_TOKEN` secret here (*Settings → Secrets and variables → Actions*).
Nothing else needs a stored credential.
