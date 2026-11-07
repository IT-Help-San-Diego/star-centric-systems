#!/bin/bash
# verify.sh: starcentric.systems static-site invariant gate. Exits non-zero on any failure.
# Modelled on the tetrasemaphore.systems gate (site/verify.sh), with the attribute, nesting and metadata
# checks done by an HTML parser rather than by regexes. Offline and deterministic: it reads the repository
# only. Set STARCENTRIC_RELEASE=1 to make the DRAFT marker, and any HTML comment, a failure.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

python3 -I - <<'PY'
import base64, hashlib, html, json, os, re, subprocess, sys, unicodedata
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
CSP_TEMPLATE = ("default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; "
                "worker-src 'none'; script-src 'none'; img-src 'self' data:; font-src 'self'; style-src 'self' '{hash}'; "
                "connect-src 'self'; media-src 'self'; manifest-src 'self'; require-trusted-types-for 'script'; "
                "trusted-types 'none'; upgrade-insecure-requests")
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
        if csp != CSP_TEMPLATE.format(hash=hp): bad(f"{PAGE}: meta CSP is not the family policy with the style hash '{hp}'")
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
            expected["SecurityHeadersConfig"]["ContentSecurityPolicy"]["ContentSecurityPolicy"] = CSP_TEMPLATE.format(hash=hp)
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
        self.stack = []; self.ids = []; self.hrefs = []; self.h1 = 0; self.links = 0; self.comments = []
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
            if "http-equiv" in a and a["http-equiv"] != "Content-Security-Policy": bad(f"{PAGE}: http-equiv other than Content-Security-Policy: {a['http-equiv']}")
            if "name" in a:
                if a["name"] == "author": bad(f"{PAGE}: <meta name=\"author\"> is not allowed (name only in the license line)")
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

if re.search(r"<script\b", raw, re.I): bad(f"{PAGE}: <script present anywhere in the file, comments included")
au = Audit(); au.feed(raw); au.close()
if au.stack: bad(f"{PAGE}: unclosed tags at end: {au.stack}")
if au.h1 != 1: bad(f"{PAGE}: exactly one <h1> required, found {au.h1}")
if au.links != 1: bad(f"{PAGE}: exactly one <link> (canonical) required, found {au.links}")
for h in au.hrefs:
    if h.startswith("#") and h[1:] not in au.ids: bad(f"{PAGE}: fragment link {h} resolves to no id")
if au.main_children != [("section", s) for s in SECTIONS]: bad(f"{PAGE}: <main> must contain exactly the sections {SECTIONS} in order; found {au.main_children}")
fam = tuple(h for h in au.footer_hrefs if h in FAMILY)
if fam != FAMILY: bad(f"{PAGE}: footer family links must be exactly {FAMILY} in order; found {fam}")
if au.footer_hrefs.count(REPO_URL) != 1: bad(f"{PAGE}: footer must link the repository exactly once")
if au.footer_hrefs.count(LICENSE_URL) != 1: bad(f"{PAGE}: footer must link the license exactly once")
if "main" not in au.ids or "family" not in au.ids: bad(f"{PAGE}: ids main and family required")
say("OK: no forbidden elements or attributes, hrefs https/root/fragment, one canonical link, meta rules, nesting, unique ids, fragments resolve, sections and footer in order, tags balanced")

# 4. Text rules on the unescaped text: em dashes, code points, local paths, placeholders, the author's name once in the license line.
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
name_hits = [m.start() for m in re.finditer(r"Carey James Balboa", norm)]
if len(name_hits) != 1 or norm.count("Balboa") != 1 or not foot or not (foot.start() < name_hits[0] < foot.end()):
    bad(f"{PAGE}: the author's name must appear exactly once, inside the footer license line (full name {len(name_hits)}, surname {norm.count('Balboa')})")
say(f"OK: em dashes = {em}; en dashes = {en} (informational); code points assigned and printable; no local paths or placeholders; author name only in the license line")

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
        else: say(f"NOTE: page carries the draft marker '{marker}' (wording and license line not yet final)")
if release and au.comments: bad(f"{PAGE}: {len(au.comments)} HTML comment(s) present in a release check (a released page carries none)")
if "PLACEHOLDER" in raw: bad(f"{PAGE}: placeholder present")

# 7. Repository privacy gate: no private dumps, doorbells, hand-offs or transcripts tracked; no local paths in tracked text files.
try:
    tracked = subprocess.check_output(["git", "ls-files"], text=True, stderr=subprocess.DEVNULL).splitlines()
except Exception:
    tracked = []
FORBIDDEN_GIT = ("research artifacts/", "private_research_vault/", "wispr", "transcript", ".jsonl", ".sqlite", "doorbell", "handoff", ".ds_store", ".secrets", ".env")
for tf in tracked:
    tfl = tf.lower()
    if any(tok in tfl for tok in FORBIDDEN_GIT): bad(f"forbidden private/dump path tracked in git: {tf}")
    if tf.endswith((".md", ".sh", ".json", ".html", "Makefile", ".txt")) and os.path.exists(tf):
        body = open(tf, encoding="utf-8", errors="replace").read()
        if home_pat in body or tilde_pat in body or ptmp_pat in body: bad(f"{tf}: leaked local filesystem path")
say("OK: git tracked-files privacy gate clean; no local paths in tracked text files")

if FAIL == 0:
    say("verify.sh: ALL CHECKS PASS"); sys.exit(0)
say("verify.sh: FAILURES PRESENT"); sys.exit(1)
PY
