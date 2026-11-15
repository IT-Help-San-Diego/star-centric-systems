#!/bin/bash
# verify.sh: starcentric.systems static-site invariant gate. Exits non-zero on any failure.
# Modelled on the tetrasemaphore.systems gate (site/verify.sh), with the attribute, nesting and metadata
# checks done by an HTML parser rather than by regexes. Offline and deterministic: it reads the repository
# only. Set STARCENTRIC_RELEASE=1 to make the DRAFT marker, and any HTML comment, a failure. In release mode the gate
# also reads the clock once, to refuse a security.txt whose Expires date has passed.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

python3 -I - <<'PY'
import base64, datetime, hashlib, html, json, os, re, subprocess, sys, unicodedata
from html.parser import HTMLParser

FAIL = 0
def say(msg): print(msg)
def bad(msg):
    global FAIL
    print("FAIL: " + msg)
    FAIL = 1

PAGE = "index.html"
POLICY = "infra/cloudfront/security-headers.json"
POLICY_NAME = "starcentric-security-headers"
CANONICAL = "https://starcentric.systems/"
REPO_URL = "https://github.com/IT-Help-San-Diego/star-centric-systems"
LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
# The response header carries the whole policy. The meta element carries the same policy minus the directives a browser
# ignores when a policy arrives in a meta element (frame-ancestors, report-uri, sandbox). An inert directive would claim a
# defence the meta policy does not give, and it logs a console message on every load. frame-ancestors works in the header
# only, so it stays there and must not be added back to the meta policy.
HEADER_CSP_TEMPLATE = ("default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; "
                "worker-src 'none'; script-src 'none'; img-src 'self' data:; font-src 'self'; style-src 'self' '{hash}'; "
                "connect-src 'self'; media-src 'self'; manifest-src 'self'; require-trusted-types-for 'script'; "
                "trusted-types 'none'; upgrade-insecure-requests")
META_IGNORED = ("frame-ancestors", "report-uri", "sandbox")
META_CSP_TEMPLATE = HEADER_CSP_TEMPLATE.replace("frame-ancestors 'none'; ", "")
FAMILY = ("https://it-help.tech/", "https://intellectualresistance.com/", "https://calibrationscope.com/",
          "https://resolutionscope.com/", "https://tetrasemaphore.systems/", "https://organiccomputer.me/")
SECTIONS = ("roof", "keystone", "method", "instruments", "record")
# The whole CloudFront policy the family ships (tetrasemaphore.systems), minus Comment, with the CSP as a template.
EXPECTED_POLICY = json.loads(r"""{
  "Name": "starcentric-security-headers",
  "SecurityHeadersConfig": {
    "FrameOptions": {
      "Override": true,
      "FrameOption": "DENY"
    },
    "ReferrerPolicy": {
      "Override": true,
      "ReferrerPolicy": "no-referrer"
    },
    "ContentSecurityPolicy": {
      "Override": true,
      "ContentSecurityPolicy": "__CSP__"
    },
    "ContentTypeOptions": {
      "Override": true
    },
    "StrictTransportSecurity": {
      "Override": true,
      "IncludeSubdomains": true,
      "Preload": true,
      "AccessControlMaxAgeSec": 63072000
    }
  },
  "CustomHeadersConfig": {
    "Quantity": 5,
    "Items": [
      {
        "Header": "Permissions-Policy",
        "Value": "interest-cohort=(), accelerometer=(), ambient-light-sensor=(), battery=(), bluetooth=(), browsing-topics=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), serial=(), storage-access=(), sync-xhr=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()",
        "Override": true
      },
      {
        "Header": "Cross-Origin-Opener-Policy",
        "Value": "same-origin",
        "Override": true
      },
      {
        "Header": "Cross-Origin-Resource-Policy",
        "Value": "same-origin",
        "Override": true
      },
      {
        "Header": "Cross-Origin-Embedder-Policy",
        "Value": "credentialless",
        "Override": true
      },
      {
        "Header": "X-Permitted-Cross-Domain-Policies",
        "Value": "none",
        "Override": true
      }
    ]
  }
}""")
EM_DASHES = "".join(chr(c) for c in (0x2014, 0x2015, 0x2E3A, 0x2E3B, 0xFE58))
EN_DASH = chr(0x2013)

if not os.path.exists(PAGE):
    bad(f"{PAGE}: missing"); print("verify.sh: FAILURES PRESENT"); sys.exit(1)
blob = open(PAGE, "rb").read()

# 1. Byte level: strict UTF-8, no BOM, no CR, no NUL, doctype first, lang=en, charset meta first in head and inside the first 1024 bytes.
try:
    raw = blob.decode("utf-8", errors="strict")
except UnicodeDecodeError as e:
    bad(f"{PAGE}: not strict UTF-8: {e}"); raw = blob.decode("utf-8", errors="replace")
if blob.startswith(b"\xef\xbb\xbf"): bad(f"{PAGE}: UTF-8 BOM present")
if b"\r" in blob: bad(f"{PAGE}: carriage return present")
if b"\x00" in blob: bad(f"{PAGE}: NUL byte present")
if not raw.startswith("<!DOCTYPE html>"): bad(f"{PAGE}: does not start with <!DOCTYPE html>")
if '<html lang="en">' not in raw: bad(f"{PAGE}: missing <html lang=\"en\">")
head = re.search(r"<head>(.*?)</head>", raw, re.S)
head_txt = head.group(1) if head else ""
if not head: bad(f"{PAGE}: no <head>")
else:
    first_meta = re.search(r"<meta\b[^>]*>", head_txt)
    if not first_meta or first_meta.group(0) != '<meta charset="utf-8">':
        bad(f"{PAGE}: first <meta> in head must be <meta charset=\"utf-8\">")
    if blob.find(b'<meta charset="utf-8">') > 1024: bad(f"{PAGE}: charset meta must sit inside the first 1024 bytes")
say("OK: strict UTF-8, no BOM/CR/NUL, doctype, lang, charset first and early")

# 2. Exactly one literal <style> block, no fetches in it, its sha256 pinned in the meta CSP (which precedes it) and in the header policy, which must equal the family policy.
style_tags = re.findall(r"<style\b[^>]*>", raw, re.I)
if style_tags != ["<style>"]: bad(f"{PAGE}: every <style> tag must be the one literal <style> block; found {style_tags}")
styles = re.findall(r"<style>(.*?)</style>", raw, re.S)
if len(styles) != 1: bad(f"{PAGE}: expected exactly one <style> block, found {len(styles)}")
hp = None
if styles:
    style = styles[0]
    if re.search(r"@import\b|url\s*\(|image-set\s*\(|\bsrc\s*:|behavior\s*:|-moz-binding|expression\s*\(", style, re.I):
        bad(f"{PAGE}: <style> contains @import, url(), image-set(), src:, behavior:, -moz-binding or expression()")
    hp = "sha256-" + base64.b64encode(hashlib.sha256(style.encode("utf-8")).digest()).decode()
    mcs = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)"', raw)
    if len(mcs) != 1: bad(f"{PAGE}: exactly one meta CSP required, found {len(mcs)}")
    else:
        csp = mcs[0]
        if csp != META_CSP_TEMPLATE.format(hash=hp): bad(f"{PAGE}: meta CSP is not the family policy, minus the directives a meta element cannot deliver, with the style hash '{hp}'")
        if "PLACEHOLDER" in csp: bad(f"{PAGE}: placeholder hash still in meta CSP")
    pos_csp = raw.find('<meta http-equiv="Content-Security-Policy"')
    if pos_csp < 0 or pos_csp > raw.find("<style>"): bad(f"{PAGE}: the meta CSP must precede the <style> block")
    if not os.path.exists(POLICY): bad(f"{POLICY}: missing")
    else:
        try:
            pol_txt = open(POLICY, encoding="utf-8").read()
            cfg = json.loads(pol_txt)["ResponseHeadersPolicyConfig"]
            comment = cfg.pop("Comment", "")
            if len(comment) > 128: bad(f"{POLICY}: Comment is {len(comment)} characters; CloudFront allows 128")
            if any(ch in EM_DASHES for ch in json.dumps(cfg, ensure_ascii=False) + comment): bad(f"{POLICY}: em dash present")
            expected = json.loads(json.dumps(EXPECTED_POLICY))
            expected["SecurityHeadersConfig"]["ContentSecurityPolicy"]["ContentSecurityPolicy"] = HEADER_CSP_TEMPLATE.format(hash=hp)
            if cfg.get("Name") != POLICY_NAME: bad(f"{POLICY}: Name must be {POLICY_NAME}")
            if cfg != expected:
                for k in sorted(set(cfg) | set(expected)):
                    if cfg.get(k) != expected.get(k): bad(f"{POLICY}: {k} differs from the family policy (or the style hash is stale)")
        except Exception as e:
            bad(f"{POLICY}: unreadable or malformed: {e}")
    say(f"OK: one <style> block, sha256 pinned in the meta CSP and in {POLICY}, policy equals the family policy ({hp})")

# 3. Parser pass: forbidden elements and attributes, href rule, meta rules, nesting, ids, fragments, section and footer order, balance.
VOID = {"meta", "link", "br", "hr", "img", "input", "source", "wbr", "area", "base", "col", "embed", "param", "track"}
FORBIDDEN_TAGS = {"script", "noscript", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "input", "button",
                  "textarea", "select", "option", "video", "audio", "img", "picture", "source", "track", "svg", "math", "canvas",
                  "base", "template", "slot", "map", "area", "portal", "dialog"}
FORBIDDEN_ATTRS = {"style", "ping", "srcset", "src", "poster", "data", "formaction", "action", "background", "dynsrc", "lowsrc",
                   "xlink:href", "contenteditable", "autofocus", "target"}
BLOCK = {"p", "div", "ul", "ol", "dl", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "details", "blockquote", "pre",
         "table", "nav", "header", "footer", "main", "aside", "hr", "figure", "address", "fieldset"}
ALLOWED_META_NAMES = {"viewport", "description", "referrer", "color-scheme", "twitter:card", "twitter:title", "twitter:description"}

class Audit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []; self.ids = []; self.hrefs = []; self.h1 = 0; self.links = 0; self.comments = []; self.csp_metas = []
        self.main_children = []; self.footer_hrefs = []; self.in_footer = False; self.details_first = {}
    def parent(self): return self.stack[-1] if self.stack else None
    def handle_starttag(self, t, attrs):
        a = {}
        for k, v in attrs:
            if k in a: bad(f"{PAGE}: duplicate attribute {k} on <{t}> at line {self.getpos()[0]}")
            a[k] = (v or "")
        if t in FORBIDDEN_TAGS: bad(f"{PAGE}: <{t}> is not allowed on this page (line {self.getpos()[0]})")
        for k, v in a.items():
            if k.startswith("on") or k in FORBIDDEN_ATTRS: bad(f"{PAGE}: forbidden attribute {k}= on <{t}> (line {self.getpos()[0]})")
            if k == "href":
                v2 = v.strip()
                if re.sub(r"\s", "", v2).lower().startswith(("javascript:", "data:", "vbscript:")): bad(f"{PAGE}: scripted or data href (line {self.getpos()[0]})")
                if v2.startswith("//") or not (v2.startswith("#") or v2.startswith("/") or v2.startswith("https://")): bad(f"{PAGE}: href must be a fragment, a root path or https: {v2!r}")
                if t == "a": self.hrefs.append(v2)
                if self.in_footer: self.footer_hrefs.append(v2)
            if k == "id":
                if v in self.ids: bad(f"{PAGE}: duplicate id {v!r}")
                self.ids.append(v)
        if t == "link":
            self.links += 1
            if a != {"rel": "canonical", "href": CANONICAL}: bad(f"{PAGE}: only <link rel=\"canonical\" href=\"{CANONICAL}\"> is allowed: {a}")
        if t == "meta":
            if a.get("http-equiv", "").lower() == "content-security-policy": self.csp_metas.append(a.get("content", ""))
            if "http-equiv" in a and a["http-equiv"] != "Content-Security-Policy": bad(f"{PAGE}: http-equiv other than Content-Security-Policy: {a['http-equiv']}")
            if "name" in a:
                if a["name"] == "author": bad(f"{PAGE}: <meta name=\"author\"> is not allowed (the page carries no personal name)")
                elif a["name"] == "referrer" and a.get("content") != "no-referrer": bad(f"{PAGE}: meta referrer must be no-referrer")
                elif a["name"] not in ALLOWED_META_NAMES: bad(f"{PAGE}: unexpected meta name {a['name']!r}")
            if "property" in a and not a["property"].startswith("og:"): bad(f"{PAGE}: unexpected meta property {a['property']!r}")
        if t == "h1": self.h1 += 1
        if t == "a" and "a" in self.stack: bad(f"{PAGE}: nested <a> (line {self.getpos()[0]})")
        if t in BLOCK and "p" in self.stack: bad(f"{PAGE}: block element <{t}> inside <p> (line {self.getpos()[0]})")
        par = self.parent()
        if t == "li" and par not in ("ul", "ol"): bad(f"{PAGE}: <li> outside a list (line {self.getpos()[0]})")
        if par in ("ul", "ol") and t != "li": bad(f"{PAGE}: <{t}> as a direct child of <{par}> (line {self.getpos()[0]})")
        if t in ("dt", "dd") and par != "dl": bad(f"{PAGE}: <{t}> outside <dl> (line {self.getpos()[0]})")
        if par == "dl" and t not in ("dt", "dd"): bad(f"{PAGE}: <{t}> as a direct child of <dl> (line {self.getpos()[0]})")
        if par == "details":
            n = self.details_first.get(len(self.stack), 0)
            if n == 0 and t != "summary": bad(f"{PAGE}: first child of <details> must be <summary> (line {self.getpos()[0]})")
            self.details_first[len(self.stack)] = n + 1
        if t == "summary" and par != "details": bad(f"{PAGE}: <summary> outside <details> (line {self.getpos()[0]})")
        if par == "main": self.main_children.append((t, a.get("id")))
        if t == "footer": self.in_footer = True
        if t not in VOID: self.stack.append(t)
        if t == "details": self.details_first[len(self.stack)] = 0
    def handle_startendtag(self, t, attrs):
        if t not in VOID: bad(f"{PAGE}: self-closing non-void <{t}/> (line {self.getpos()[0]})")
        self.handle_starttag(t, attrs)
        if t not in VOID and self.stack and self.stack[-1] == t: self.stack.pop()
    def handle_endtag(self, t):
        if t in VOID: return
        if not self.stack or self.stack[-1] != t: bad(f"{PAGE}: unbalanced </{t}> at line {self.getpos()[0]} (open: {self.stack[-3:]})")
        else:
            if t == "details": self.details_first.pop(len(self.stack), None)
            self.stack.pop()
        if t == "footer": self.in_footer = False
    def handle_comment(self, data): self.comments.append(data)
    def handle_decl(self, decl):
        if decl != "DOCTYPE html": bad(f"{PAGE}: unexpected declaration {decl!r}")
    def handle_pi(self, data): bad(f"{PAGE}: processing instruction present")
    def unknown_decl(self, data): bad(f"{PAGE}: marked section present; a browser reads it as a comment")

def check_meta_policies(page, metas):
    """Exactly one meta policy, however the element is spelled, and none of the directives a meta element cannot deliver."""
    if hp and metas != [META_CSP_TEMPLATE.format(hash=hp)]:
        bad(f"{page}: the parser finds {len(metas)} meta policy element(s); exactly one is allowed, the meta policy with the style hash '{hp}'")
    for c in metas:
        for d in META_IGNORED:
            if d in c: bad(f"{page}: a meta policy carries {d}, which browsers ignore in a meta element; it belongs in the response header only")

if re.search(r"<script\b", raw, re.I): bad(f"{PAGE}: <script present anywhere in the file, comments included")
au = Audit(); au.feed(raw); au.close()
check_meta_policies(PAGE, au.csp_metas)
if au.stack: bad(f"{PAGE}: unclosed tags at end: {au.stack}")
if au.h1 != 1: bad(f"{PAGE}: exactly one <h1> required, found {au.h1}")
if au.links != 1: bad(f"{PAGE}: exactly one <link> (canonical) required, found {au.links}")
for h in au.hrefs:
    if h.startswith("#") and h[1:] not in au.ids: bad(f"{PAGE}: fragment link {h} resolves to no id")
if au.main_children != [("section", s) for s in SECTIONS]: bad(f"{PAGE}: <main> must contain exactly the sections {SECTIONS} in order; found {au.main_children}")
fam = tuple(h for h in au.footer_hrefs if h in FAMILY)
if fam != FAMILY: bad(f"{PAGE}: footer family links must be exactly {FAMILY} in order; found {fam}")
if au.footer_hrefs.count(REPO_URL) != 1: bad(f"{PAGE}: footer must link the repository exactly once")
if au.footer_hrefs.count(LICENSE_URL) != 0: bad(f"{PAGE}: footer links the license; the site owner ruled on 7 November 2026 that the page carries no copyright, name or license line")
if "main" not in au.ids or "family" not in au.ids: bad(f"{PAGE}: ids main and family required")
say("OK: no forbidden elements or attributes, hrefs https/root/fragment, one canonical link, meta rules, nesting, unique ids, fragments resolve, sections and footer in order, tags balanced")

# 4. Text rules on the unescaped text: em dashes, code points, local paths, placeholders, no personal name anywhere (site owner's ruling, 7 November 2026).
txt = html.unescape(raw)
em = sum(txt.count(ch) for ch in EM_DASHES)
if em: bad(f"{PAGE}: {em} em dash(es) present (U+2014/U+2015/U+2E3A/U+2E3B, raw or as entities)")
en = txt.count(EN_DASH)
for ch in sorted(set(txt)):
    if ord(ch) > 127 or (ord(ch) < 32 and ch not in "\n\t"):
        cat = unicodedata.category(ch)
        if unicodedata.name(ch, None) is None or cat in ("Cn", "Co", "Cs", "Cf", "Zl", "Zp", "Cc"):
            bad(f"{PAGE}: forbidden code point U+{ord(ch):04X} ({cat})")
home_pat = "/" + "Users/"
tilde_pat = "~" + "/"
ptmp_pat = "/private" + "/tmp/"
if home_pat in txt or ptmp_pat in txt or tilde_pat in txt: bad(f"{PAGE}: leaked local filesystem path")
body_text = re.sub(r"<[^>]+>", " ", re.sub(r"<!--.*?-->", " ", txt, flags=re.S))
if re.search(r"\b(?:TODO|TK|TBD|FIXME|XXX|PLACEHOLDER)\b", body_text) or re.search(r"lorem ipsum", body_text, re.I): bad(f"{PAGE}: placeholder text present")
norm = re.sub(r"[\s ]+", " ", re.sub("[" + chr(0xAD) + chr(0x200B) + "]", "", txt))
foot = re.search(r"<footer\b.*?</footer>", norm, re.S)
name_hits = re.findall(r"\b(?:Carey|Balboa)\b", norm)
if name_hits or re.search(r"(?i)\bcopyright\b", body_text) or "\u00a9" in norm:
    bad(f"{PAGE}: the page must carry no personal name and no copyright line (site owner's ruling, 7 November 2026); found {name_hits or 'a copyright mark'}")
say(f"OK: em dashes = {em}; en dashes = {en} (informational); code points assigned and printable; no local paths or placeholders; no personal name or copyright line")

# 5. Required head metadata.
if "<title>Star-Centric Systems</title>" not in head_txt: bad(f"{PAGE}: title must be Star-Centric Systems")
for needle in ('<meta name="viewport" content="width=device-width, initial-scale=1">',
               '<meta name="referrer" content="no-referrer">',
               f'<link rel="canonical" href="{CANONICAL}">',
               f'<meta property="og:url" content="{CANONICAL}">',
               '<meta name="description" content="'):
    if needle not in head_txt: bad(f"{PAGE}: missing {needle}")
say("OK: title, viewport, referrer, canonical, og:url, description present")

# 6. Draft markers and comments.
release = os.environ.get("STARCENTRIC_RELEASE") == "1"
for marker in ("<!-- DRAFT", "LICENSE LINE PENDING"):
    if marker.lower() in raw.lower():
        if release: bad(f"{PAGE}: draft marker '{marker}' present in a release check")
        else: say(f"NOTE: page carries the draft marker '{marker}' (wording not yet final)")
if release and au.comments: bad(f"{PAGE}: {len(au.comments)} HTML comment(s) present in a release check (a released page carries none)")
if "PLACEHOLDER" in raw: bad(f"{PAGE}: placeholder present")

# 7. Repository privacy gate: no private dumps, doorbells, hand-offs or transcripts tracked; no local paths in tracked text files.
try:
    tracked = subprocess.check_output(["git", "ls-files"], text=True, stderr=subprocess.DEVNULL).splitlines()
except Exception:
    tracked = None
FORBIDDEN_GIT = ("research artifacts/", "private_research_vault/", "wispr", "transcript", ".jsonl", ".sqlite", "doorbell", "handoff", ".ds_store", ".secrets", ".env")
if tracked is None:
    say("NOTE: not a git checkout; the tracked-files privacy gate did not run here. It runs in the repository; the four published files are checked for local paths below either way.")
else:
    for tf in tracked:
        tfl = tf.lower()
        if any(tok in tfl for tok in FORBIDDEN_GIT): bad(f"forbidden private/dump path tracked in git: {tf}")
        if tf.endswith((".md", ".sh", ".json", ".html", "Makefile", ".txt")) and os.path.exists(tf):
            body = open(tf, encoding="utf-8", errors="replace").read()
            if home_pat in body or tilde_pat in body or ptmp_pat in body: bad(f"{tf}: leaked local filesystem path")
    say("OK: git tracked-files privacy gate clean; no local paths in tracked text files")

# 8. The other published files. 404.html carries the byte-identical style block and the same meta policy; robots.txt and security.txt are well formed.
NOT_FOUND = "404.html"
ROBOTS = "robots.txt"
SECURITY = ".well-known/security.txt"
if not os.path.exists(NOT_FOUND): bad(f"{NOT_FOUND}: missing")
else:
    nb = open(NOT_FOUND, "rb").read()
    try:
        nraw = nb.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        bad(f"{NOT_FOUND}: not strict UTF-8: {e}"); nraw = nb.decode("utf-8", errors="replace")
    if nb.startswith(b"\xef\xbb\xbf") or b"\r" in nb or b"\x00" in nb: bad(f"{NOT_FOUND}: BOM, carriage return or NUL present")
    if not nraw.startswith("<!DOCTYPE html>") or '<html lang="en">' not in nraw: bad(f"{NOT_FOUND}: doctype or lang missing")
    nstyles = re.findall(r"<style>(.*?)</style>", nraw, re.S)
    if re.findall(r"<style\b[^>]*>", nraw, re.I) != ["<style>"] or len(nstyles) != 1: bad(f"{NOT_FOUND}: exactly one literal <style> block required")
    elif styles and nstyles[0] != styles[0]: bad(f"{NOT_FOUND}: its <style> block must be byte-identical to {PAGE}'s, because one hash in the header policy serves both pages")
    nmcs = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)"', nraw)
    if len(nmcs) != 1 or (hp and nmcs[0] != META_CSP_TEMPLATE.format(hash=hp)): bad(f"{NOT_FOUND}: meta CSP is not the meta policy with the style hash '{hp}'")
    if nraw.find('<meta http-equiv="Content-Security-Policy"') < 0 or nraw.find('<meta http-equiv="Content-Security-Policy"') > nraw.find("<style>"): bad(f"{NOT_FOUND}: the meta CSP must precede the <style> block")
    if re.search(r"<script\b", nraw, re.I): bad(f"{NOT_FOUND}: <script present")
    PAGE_INDEX, PAGE = PAGE, NOT_FOUND
    au2 = Audit(); au2.feed(nraw); au2.close()
    if au2.stack: bad(f"{NOT_FOUND}: unclosed tags at end: {au2.stack}")
    if au2.h1 != 1: bad(f"{NOT_FOUND}: exactly one <h1> required, found {au2.h1}")
    if au2.links != 1: bad(f"{NOT_FOUND}: exactly one <link> (canonical) required, found {au2.links}")
    for h in au2.hrefs:
        if h.startswith("#") and h[1:] not in au2.ids: bad(f"{NOT_FOUND}: fragment link {h} resolves to no id")
    if au2.main_children != [("section", "not-found")]: bad(f"{NOT_FOUND}: <main> must contain exactly the section not-found; found {au2.main_children}")
    if tuple(h for h in au2.footer_hrefs if h in FAMILY) != FAMILY: bad(f"{NOT_FOUND}: footer family links must be exactly {FAMILY} in order")
    if au2.comments: bad(f"{NOT_FOUND}: {len(au2.comments)} HTML comment(s) present (the served page carries none)")
    ntxt = html.unescape(nraw)
    if any(ntxt.count(ch) for ch in EM_DASHES): bad(f"{NOT_FOUND}: em dash present")
    for ch in sorted(set(ntxt)):
        if ord(ch) > 127 or (ord(ch) < 32 and ch not in "\n\t"):
            if unicodedata.name(ch, None) is None or unicodedata.category(ch) in ("Cn", "Co", "Cs", "Cf", "Zl", "Zp", "Cc"): bad(f"{NOT_FOUND}: forbidden code point U+{ord(ch):04X}")
    if home_pat in ntxt or ptmp_pat in ntxt or tilde_pat in ntxt: bad(f"{NOT_FOUND}: leaked local filesystem path")
    nbody = re.sub(r"<[^>]+>", " ", ntxt)
    if re.findall(r"\b(?:Carey|Balboa)\b", ntxt) or re.search(r"(?i)\bcopyright\b", nbody) or "©" in ntxt: bad(f"{NOT_FOUND}: the page must carry no personal name and no copyright line")
    if re.search(r"\b(?:TODO|TK|TBD|FIXME|XXX|PLACEHOLDER)\b", nbody) or re.search(r"lorem ipsum", nbody, re.I): bad(f"{NOT_FOUND}: placeholder text present")
    nhead = re.search(r"<head>(.*?)</head>", nraw, re.S)
    nfirst = re.search(r"<meta\b[^>]*>", nhead.group(1)) if nhead else None
    if not nfirst or nfirst.group(0) != '<meta charset="utf-8">' or nb.find(b'<meta charset="utf-8">') > 1024: bad(f"{NOT_FOUND}: first <meta> in head must be the charset meta, inside the first 1024 bytes")
    if not nhead or not re.search(r"<title>[^<]+</title>", nhead.group(1)): bad(f"{NOT_FOUND}: a non-empty <title> is required")
    check_meta_policies(NOT_FOUND, au2.csp_metas)
    PAGE = PAGE_INDEX
def read_text(path):
    """Strict UTF-8 text of a published text file, or None after saying why not."""
    try:
        b = open(path, "rb").read()
    except OSError as e:
        bad(f"{path}: unreadable ({e.__class__.__name__})"); return None
    try:
        t = b.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        bad(f"{path}: not strict UTF-8: {e}"); return None
    if b.startswith(b"\xef\xbb\xbf") or b"\r" in b or b"\x00" in b: bad(f"{path}: BOM, carriage return or NUL present")
    if home_pat in t or ptmp_pat in t or tilde_pat in t: bad(f"{path}: leaked local filesystem path")
    return t

expires = "missing"
if not os.path.exists(ROBOTS): bad(f"{ROBOTS}: missing")
else:
    rt = read_text(ROBOTS)
    if rt is not None:
        # The site owner chose on 15 November 2026 (UTC) to leave the site open to crawlers. The gate holds the file to that
        # choice: one group, for every crawler, that allows everything. A different crawl policy is a decision; change this
        # rule together with the file.
        recs = []
        for l in rt.splitlines():
            l = l.split("#", 1)[0].strip()
            if not l: continue
            m = re.match(r"(?i)^(user-agent|allow|disallow|sitemap)\s*:\s*(.*)$", l)
            if not m: bad(f"{ROBOTS}: line is not a User-agent, Allow, Disallow or Sitemap record: {l!r}"); continue
            recs.append((m.group(1).lower(), m.group(2).strip()))
        rules = [r for r in recs if r[0] != "sitemap"]
        if rules not in ([("user-agent", "*"), ("allow", "/")], [("user-agent", "*"), ("disallow", "")]):
            bad(f"{ROBOTS}: must be one group for every crawler that allows everything ('User-agent: *' then 'Allow: /'), as the site owner chose; found {rules}")
        for k, v in recs:
            if k == "sitemap" and not v.startswith(CANONICAL): bad(f"{ROBOTS}: a Sitemap must be an address under {CANONICAL}")
if not os.path.exists(SECURITY): bad(f"{SECURITY}: missing")
else:
    st = read_text(SECURITY)
    if st is not None:
        sfields = []
        for l in st.splitlines():
            if not l.strip() or l.lstrip().startswith("#"): continue
            m = re.match(r"^([A-Za-z-]+):\s+(\S.*)$", l)
            if not m: bad(f"{SECURITY}: line is not a 'Name: value' field: {l!r}"); continue
            sfields.append((m.group(1).lower(), m.group(2).strip()))
        contacts = [v for k, v in sfields if k == "contact"]
        exps = [v for k, v in sfields if k == "expires"]
        canons = [v for k, v in sfields if k == "canonical"]
        if not contacts or any(not re.match(r"^(mailto:[^@\s]+@[^@\s]+|https://\S+|tel:\S+)$", c) for c in contacts):
            bad(f"{SECURITY}: at least one Contact is required and every Contact must be a mailto:, https: or tel: address")
        if len(exps) != 1: bad(f"{SECURITY}: exactly one Expires field is required, found {len(exps)}")
        else:
            expires = exps[0]
            try:
                when = datetime.datetime.fromisoformat(expires[:-1] + "+00:00" if expires[-1:] in ("Z", "z") else expires)
                if when.tzinfo is None: raise ValueError("no time zone")
                if release and when <= datetime.datetime.now(datetime.timezone.utc):
                    bad(f"{SECURITY}: Expires {expires} has passed; a released site must not publish an expired security.txt")
            except ValueError:
                bad(f"{SECURITY}: Expires is not a real RFC 3339 timestamp with a time zone: {expires!r}")
        if CANONICAL + SECURITY not in canons: bad(f"{SECURITY}: one Canonical field must be {CANONICAL + SECURITY}")
say(f"OK: {NOT_FOUND} carries the same style block and meta policy as {PAGE}; {ROBOTS} allows every crawler, as chosen; {SECURITY} well formed (expires {expires})")

if FAIL == 0:
    say("verify.sh: ALL CHECKS PASS"); sys.exit(0)
say("verify.sh: FAILURES PRESENT"); sys.exit(1)
PY
