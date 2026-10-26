# cg-publish-gate

Every Common Ground site is checked against cg-facts before it can publish.

A site repo calls this reusable workflow on each pull request. The workflow
builds the site, reads the rendered output (page text, titles, meta
descriptions, image alt text, JSON-LD, llms.txt, sitemap) and fails the check
when the output prints something cg-facts does not approve:

- a retired figure or claim
- a title that is not the person's public title
- a misspelled partner name or brand
- a retired product name
- an em dash, en dash or double hyphen
- a dollar figure of $1M or more that is not an approved cg-facts fact
- a walled personal subject

With the check required on `main`, a failing pull request cannot merge, so
Cloudflare Workers Builds never deploys it.

## Wire a site

`.github/workflows/cg-facts-gate.yml` in the site repo:

```yaml
name: cg-facts gate
on:
  pull_request:
  push:
    branches: [main]
jobs:
  gate:
    uses: common-ground-ventures/cg-publish-gate/.github/workflows/gate.yml@v1
    with:
      site-dir: .            # rendered output folder, e.g. dist for Astro
      build-command: ""      # e.g. npm ci && npm run build
      node-version: ""       # e.g. "22"
    secrets: inherit
```

Then add the repo to `gate/consumers.yaml` in cg-facts so the publish step
gives it the gate bundle secret, and require the `gate / cg-facts gate` check
on `main`.

## Known findings

A site that already prints findings on the day it is wired keeps them in
`cg-facts-baseline.json`. Those show as known debt and do not fail; anything
new fails. The baseline only shrinks: fix the page or the fact, then drop the
entry.

Write one from a local checkout:

```
python3 scan_site.py --export <bundle> --site . --baseline cg-facts-baseline.json --write-baseline
```

## Where the rules come from

The scanner is a copy of `gate/scan_site.py` from cg-facts, refreshed by
pull request. Rules and approved figures are compiled in cg-facts and reach
site CI only as the org secret `CG_FACTS_GATE_BUNDLE`. The readable export
lives in the private repo `common-ground-ventures/cg-facts-export`. Ledger
rows never leave cg-facts.

## Review rule

Infrastructure. Changes wait for Robby's review.
