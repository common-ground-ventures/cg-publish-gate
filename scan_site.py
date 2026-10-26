#!/usr/bin/env python3
"""cg-facts publish gate: scan a built site against the public-safe fact export.

Reads only the export (rules.json, approved.json). Standard library only, so it
runs in any site repo's CI without installing anything.

    python3 scan_site.py --export <export dir | bundle file> --site <built site dir>
        [--baseline cg-facts-baseline.json] [--write-baseline]
        [--summary <markdown out>] [--json <json out>]

Exit 0 when every finding is in the baseline, 1 when there is a new finding,
2 on a usage or input error.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import json
import os
import re
import sys
from html.parser import HTMLParser

TEXT_EXT = (".html", ".htm", ".txt", ".xml", ".json", ".md", ".webmanifest")
SKIP_DIRS = {".git", "node_modules", ".github", ".cg-publish-gate", ".wrangler", ".astro"}
SKIP_FILES = {"package.json", "package-lock.json", "wrangler.jsonc", "wrangler.json",
              "wrangler.toml", "cg-facts-baseline.json", "tsconfig.json", "vercel.json"}
# Every tag boundary separates words except inline formatting, so text from
# neighboring cells, links and spans never fuses into one word.
INLINE_TAGS = {"b", "i", "em", "strong", "u", "s", "sup", "sub", "small", "abbr",
               "code", "mark", "q", "cite", "time", "wbr"}
META_NAMES = re.compile(r"^(description|keywords|author|og:.*|twitter:.*|citation_.*)$", re.I)
TEXT_ATTRS = ("alt", "title", "aria-label")

DOLLAR = re.compile(
    r"\$\s?(\d[\d,]*(?:\.\d+)?)\s?(K|M|B|MM|thousand|million|billion)?\b(\+)?", re.I)
MULT = {"k": 1e3, "thousand": 1e3, "m": 1e6, "mm": 1e6, "million": 1e6,
        "b": 1e9, "billion": 1e9}


# ---------------------------------------------------------------- extraction

class _Extractor(HTMLParser):
    """Collect reader-visible text plus the attributes crawlers read."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []          # (text, line)
        self.skip = 0
        self.ldjson = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("style",):
            self.skip += 1
        elif tag == "script":
            if (a.get("type") or "").lower() == "application/ld+json":
                self.ldjson = True
            else:
                self.skip += 1
        if tag == "meta":
            key = a.get("name") or a.get("property") or ""
            if META_NAMES.match(key) and a.get("content"):
                self._add(a["content"])
        for attr in TEXT_ATTRS:
            if a.get(attr):
                self._add(a[attr])
        if tag not in INLINE_TAGS:
            self._add("\n")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "style" and self.skip:
            self.skip -= 1
        elif tag == "script":
            if self.ldjson:
                self.ldjson = False
            elif self.skip:
                self.skip -= 1
        if tag not in INLINE_TAGS:
            self._add("\n")

    def handle_data(self, data):
        if self.skip:
            return
        if self.ldjson:
            try:
                data = " \n ".join(_json_strings(json.loads(data)))
            except ValueError:
                pass
        self._add(data)

    def _add(self, text):
        self.parts.append((text, self.getpos()[0]))


def _json_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _json_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _json_strings(v)


def extract(path):
    """Return (text, offsets) where offsets maps text positions to source lines."""
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read()
    if path.endswith((".html", ".htm")):
        p = _Extractor()
        p.feed(raw)
        p.close()
        parts = p.parts
    elif path.endswith(".json"):
        try:
            parts = [(s + "\n", 1) for s in _json_strings(json.loads(raw))]
        except ValueError:
            parts = [(raw, 1)]
    else:
        parts = [(line + "\n", i + 1) for i, line in enumerate(raw.split("\n"))]
    text, offsets, pos = [], [], 0
    for chunk, line in parts:
        chunk = html.unescape(chunk) if not path.endswith((".html", ".htm")) else chunk
        offsets.append((pos, line))
        text.append(chunk)
        pos += len(chunk)
    return "".join(text), offsets


def line_at(offsets, pos):
    line = 1
    for start, ln in offsets:
        if start > pos:
            break
        line = ln
    return line


# ------------------------------------------------------------------- matching

def dollar_value(m):
    num = float(m.group(1).replace(",", ""))
    unit = (m.group(2) or "").lower()
    return num * MULT.get(unit, 1)


def path_matches(rel, globs):
    return any(fnmatch.fnmatch(rel, g) for g in globs or [])


def window_has(text, start, end, pattern, window):
    lo, hi = max(0, start - window), min(len(text), end + window)
    return re.search(pattern, text[lo:hi]) is not None


def snippet(text, start, end, width=60):
    lo, hi = max(0, start - width), min(len(text), end + width)
    s = re.sub(r"\s+", " ", text[lo:hi]).strip()
    return s


def scan_text(rel, text, offsets, rules, approved, threshold):
    found = []

    def add(rule_id, m_start, m_end, match, message):
        found.append({
            "rule": rule_id,
            "file": rel,
            "line": line_at(offsets, m_start),
            "match": match,
            "context": snippet(text, m_start, m_end),
            "message": message,
        })

    for r in rules["rules"]:
        for m in re.finditer(r["pattern"], text):
            s, e = m.span()
            w = r.get("window", 160)
            if r.get("near") or r.get("paths"):
                near_ok = r.get("near") and window_has(text, s, e, r["near"], w)
                if not (near_ok or path_matches(rel, r.get("paths"))):
                    continue
            if r.get("require") and not window_has(text, s, e, re.escape(r["require"]), w):
                continue
            if r.get("unless") and window_has(text, s, e, r["unless"], 24):
                continue
            add(r["id"], s, e, m.group(0), r["message"])

    if rules.get("wall_word_hashes"):
        hashes = set(rules["wall_word_hashes"])
        for m in re.finditer(r"[^\W\d_]+", text):
            h = hashlib.sha256(("cg-facts-wall:" + m.group(0).lower()).encode()).hexdigest()
            if h in hashes:
                add("WALL-WORD", m.start(), m.end(), "[walled word]",
                    "Walled personal name on a public page.")

    if rules.get("wiped_name_hashes"):
        by_len = {}
        for e in rules["wiped_name_hashes"]:
            by_len.setdefault(e["words"], set()).add(e["hash"])
        toks = list(re.finditer(r"[^\W\d_]+", text))
        for n, hashes in by_len.items():
            for i in range(len(toks) - n + 1):
                key = " ".join(t.group(0).lower() for t in toks[i:i + n])
                if hashlib.sha256(("cg-facts-wiped:" + key).encode()).hexdigest() in hashes:
                    add("WIPED-PERSON", toks[i].start(), toks[i + n - 1].end(),
                        text[toks[i].start():toks[i + n - 1].end()],
                        "Names a person wiped from cg-facts. Remove every mention and link.")

    for m in DOLLAR.finditer(text):
        val = dollar_value(m)
        if val < threshold:
            continue
        if round(val) in approved:
            continue
        add("FIGURE-UNAPPROVED", m.start(), m.end(), m.group(0).strip(),
            "Dollar figure with no approved cg-facts fact. Add the fact in cg-facts "
            "first (with its source row), or cut the figure.")
    return found


# --------------------------------------------------------------------- driver

def load_ignore(site):
    """Honor .assetsignore: files Workers never uploads are never published."""
    globs = []
    p = os.path.join(site, ".assetsignore")
    if os.path.isfile(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                globs.append(line.rstrip("/"))
    return globs


def ignored(rel, globs):
    for g in globs:
        g2 = g.lstrip("/")
        if fnmatch.fnmatch(rel, g2) or rel.startswith(g2 + "/") or fnmatch.fnmatch(
                os.path.basename(rel), g2):
            return True
    return False


def walk(site):
    globs = load_ignore(site)
    for root, dirs, files in os.walk(site):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fn in sorted(files):
            if fn in SKIP_FILES or not fn.endswith(TEXT_EXT):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, site).replace(os.sep, "/")
            if ignored(rel, globs):
                continue
            yield path, rel


def load_export(src):
    """An export folder, a bundle.json, or a base64 gzip bundle (the org secret)."""
    if os.path.isdir(src):
        rules = json.load(open(os.path.join(src, "gate", "rules.json")))
        approved = json.load(open(os.path.join(src, "gate", "approved.json")))
        meta = json.load(open(os.path.join(src, "EXPORT.json")))
    else:
        raw = open(src, "rb").read().strip()
        if not raw.startswith(b"{"):
            import base64
            import gzip
            raw = gzip.decompress(base64.b64decode(raw))
        b = json.loads(raw)
        rules, approved, meta = b["rules"], b["approved"], b
    return rules, {round(v) for v in approved["dollar_values"]}, meta


# ------------------------------------------------- structure (Jacob's list)

NAV_BLOCK = re.compile(r"<(nav|header|footer)\b.*?</\1>", re.S | re.I)
DEAD_A = re.compile(r"<a\b(?![^>]*\bhref=)[^>]*>|<a\b[^>]*\bhref=\"(?:#|javascript:[^\"]*)?\"[^>]*>", re.I)
# A button in a nav or footer is a link a crawler cannot follow, unless it is
# a menu toggle (aria-expanded or aria-controls). Frameworks drop onclick from
# the HTML, so every such button counts.
NAV_BUTTON = re.compile(r"<button\b(?![^>]*\baria-(?:expanded|controls)=)[^>]*>", re.I)
ZERO_FIGURE = re.compile(r"\$0(?:\.0+)?\s?[KMB]?\+|(?<![\d.])0%\+")


def _finding(rule, rel, line, match, message):
    return {"rule": rule, "file": rel, "line": line, "match": match, "context": match, "message": message}


def scan_structure(rel, path):
    """What a crawler meets before it reads a word: dead nav links and figures
    that only exist after JavaScript runs."""
    raw = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for blk in NAV_BLOCK.finditer(raw):
        hits = list(DEAD_A.finditer(blk.group(0)))
        if blk.group(1).lower() in ("nav", "footer"):
            hits += list(NAV_BUTTON.finditer(blk.group(0)))
        for m in hits:
            line = raw.count("\n", 0, blk.start() + m.start()) + 1
            out.append(_finding("NAV-NOT-A-LINK", rel, line, m.group(0)[:80],
                                "A nav, header or footer item crawlers cannot follow. Use <a href> to a real page."))
    text, offsets = extract(path)
    for m in ZERO_FIGURE.finditer(text):
        out.append(_finding("FIGURE-ZERO", rel, line_at(offsets, m.start()), m.group(0),
                            "A figure that reads as zero without JavaScript (a counter). Crawlers see this value. "
                            "Print the real figure in the HTML."))
    return out


def scan_site_files(site):
    """Redirects must be permanent; every sitemap URL must be a page we serve."""
    out = []
    red = os.path.join(site, "_redirects")
    if os.path.isfile(red):
        for i, line in enumerate(open(red, encoding="utf-8"), 1):
            parts = line.split("#")[0].split()
            if len(parts) < 2:
                continue
            code = parts[2] if len(parts) > 2 else "302"
            if code in ("302", "303", "307"):
                out.append(_finding("REDIRECT-TEMPORARY", "_redirects", i, " ".join(parts),
                                    f"Temporary redirect ({code}). Use 301 or 308 so search engines move the page."))
    sm = os.path.join(site, "sitemap.xml")
    if os.path.isfile(sm):
        xml = open(sm, encoding="utf-8").read()
        for m in re.finditer(r"<loc>\s*https?://[^/<]+(/[^<]*)?\s*</loc>", xml):
            p = (m.group(1) or "/").split("#")[0].split("?")[0]
            cand = [p.lstrip("/"), os.path.join(p.lstrip("/"), "index.html"), p.lstrip("/") + ".html"]
            if not any(c and os.path.isfile(os.path.join(site, c)) for c in cand) and p != "/":
                line = xml.count("\n", 0, m.start()) + 1
                out.append(_finding("SITEMAP-NOT-A-PAGE", "sitemap.xml", line, p,
                                    "Sitemap lists a URL the site does not serve as a page (missing or a redirect)."))
            if p == "/" and not os.path.isfile(os.path.join(site, "index.html")):
                out.append(_finding("SITEMAP-NOT-A-PAGE", "sitemap.xml", 1, p, "Sitemap lists / but there is no index.html."))
    return out


def fingerprint(f):
    return f"{f['rule']}|{f['file']}|{f['match']}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--export", required=True)
    ap.add_argument("--site", required=True)
    ap.add_argument("--baseline")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--summary")
    ap.add_argument("--json")
    a = ap.parse_args(argv)

    try:
        rules, approved, meta = load_export(a.export)
    except (OSError, ValueError, KeyError) as e:
        print(f"cg-facts gate: cannot read the export: {e}", file=sys.stderr)
        return 2
    if not os.path.isdir(a.site):
        print(f"cg-facts gate: site dir not found: {a.site}", file=sys.stderr)
        return 2

    findings, files = [], 0
    for path, rel in walk(a.site):
        files += 1
        text, offsets = extract(path)
        findings += scan_text(rel, text, offsets, rules, approved, rules["figure_threshold"])
        if path.endswith((".html", ".htm")):
            findings += scan_structure(rel, path)
    findings += scan_site_files(a.site)

    counts = {}
    for f in findings:
        counts[fingerprint(f)] = counts.get(fingerprint(f), 0) + 1

    if a.write_baseline:
        out = {
            "note": "Known findings on the day the gate was wired. Each entry is debt "
                    "to fix, not a permission. Shrink it; never grow it without review.",
            "export_commit": meta.get("source_commit"),
            "findings": [{"fingerprint": k, "count": v} for k, v in sorted(counts.items())],
        }
        with open(a.baseline or "cg-facts-baseline.json", "w") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=True)
            fh.write("\n")
        print(f"baseline written: {len(counts)} fingerprints, {len(findings)} findings")
        return 0

    base = {}
    if a.baseline and os.path.isfile(a.baseline):
        for e in json.load(open(a.baseline))["findings"]:
            base[e["fingerprint"]] = e["count"]

    new, known, seen = [], [], {}
    for f in findings:
        k = fingerprint(f)
        seen[k] = seen.get(k, 0) + 1
        (known if seen[k] <= base.get(k, 0) else new).append(f)
    fixed = sorted(k for k, c in base.items() if counts.get(k, 0) < c)

    for f in new:
        print(f"::error file={f['file']},line={f['line']},title=cg-facts {f['rule']}::"
              f"{f['message']} Found: {f['match']!r} in \"{f['context']}\"")

    lines = [
        "## cg-facts publish gate",
        "",
        f"Export `{str(meta.get('source_commit', '?'))[:10]}` built {meta.get('generated_at', '?')}. "
        f"Scanned {files} files.",
        "",
        f"**{'FAIL' if new else 'PASS'}**: {len(new)} new finding(s), "
        f"{len(known)} known (baseline), {len(fixed)} baseline entr(ies) now fixed.",
        "",
    ]
    if new:
        lines += ["| Rule | File | Line | Found | Context |", "|---|---|---|---|---|"]
        for f in new:
            ctx = f["context"].replace("|", "\\|")
            lines.append(f"| {f['rule']} | {f['file']} | {f['line']} | `{f['match']}` | {ctx} |")
        lines.append("")
    if known:
        by_rule = {}
        for f in known:
            by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        lines.append("Known debt by rule: " + ", ".join(
            f"{k} {v}" for k, v in sorted(by_rule.items())))
    if fixed:
        lines += ["", "Fixed since baseline (remove from cg-facts-baseline.json):"]
        lines += [f"- `{k}`" for k in fixed]
    report = "\n".join(lines) + "\n"
    print(report)
    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write(report)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"new": new, "known": known, "fixed": fixed, "files": files},
                      fh, indent=2, ensure_ascii=True)
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
