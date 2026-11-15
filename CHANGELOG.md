# Changelog

Housekeeping changes to starcentric.systems: changes that bear on no claim the page makes. A correction to a claim is not housekeeping; it is dated on the page itself.

## Next deploy

- The meta Content-Security-Policy on `index.html` and `404.html` no longer carries `frame-ancestors`. Browsers ignore that directive in a meta element and logged a warning on every load. The response header carries it on every path, and that is where it takes effect.
- `404.html`, `robots.txt` and `.well-known/security.txt` are in the repository and in the publish allowlist. They were already live. `robots.txt` and `security.txt` are byte-identical to what was served; `404.html` differs only by the meta policy line above.
- `make deploy` runs the release gate and publishes all four files with their content types.

## 15 November 2026

- First publication, from `main` at 3605870.
