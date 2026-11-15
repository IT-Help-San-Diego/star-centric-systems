# Changelog

Housekeeping changes to starcentric.systems: changes that alter nothing a reader can read or act on. A change to what the page says is not housekeeping; it is dated on the page itself. Dates are UTC.

## 15 November 2026, repository only

Nothing served changed.

- The gate was hardened after an independent review of the second deploy. It now counts meta policy elements with the parser, so a second one in any spelling fails. It refuses marked sections, which a browser reads as comments. It holds `404.html` to the placeholder, charset and title rules. It reads `robots.txt` and `security.txt` as strict UTF-8, checks them for local paths, and parses them by their own grammar. It holds `robots.txt` to the crawl policy the site owner chose, open to every crawler. It requires exactly one `Expires` in `security.txt`, a real date, and in release mode one that has not passed. Outside a git checkout it says that the tracked-files check did not run.
- `make deploy` uploads the four published files by name, with no sync before them, and refuses a bucket address that ends in a slash.

## 15 November 2026, second deploy

From `main` at 25a216a.

- The meta Content-Security-Policy on `index.html` and `404.html` no longer carries `frame-ancestors`. Browsers ignore that directive in a meta element and logged a console message on every load. The response header carries it on every path, and that is where it takes effect.
- `404.html`, `robots.txt` and `.well-known/security.txt` came into the repository and the publish allowlist. They had been served since 7 November 2026. `robots.txt` and `security.txt` are byte-identical to what was served; `404.html` differs only by the meta policy line above.
- `make deploy` runs the release gate and publishes all four files with their content types.
- Measured before and after the deploy: on both pages only the meta policy line changed. The title, the other meta tags, the links, the visible text and the body markup are identical.

## 15 November 2026, first publication

- `index.html` published, from `main` at 3605870.
