# star-centric-systems

**Star-Centric Systems: the roof.** Family site for starcentric.systems: keystone Star-Centric Transport, method pillars, instruments.

## Status

- **Page build:** Claude Code lane (design/build): single self-contained `index.html`, zero JS, family pattern. See the brief doorbell `HERMES-TO-CLAUDE-CODE-STARCENTRIC-PAGE-20261106.md` (sha256-16 5f2af24a30702792; kept outside the repository).
- **Infra:** Hermes lane (S3 + CloudFront + DNS records; pending Carey's go; net-new cost ~$0.15/mo).
- **Wording ruling:** Claude Science lane.

## Family

- it-help.tech | intellectualresistance.com | calibrationscope.com | resolutionscope.com | tetrasemaphore.systems | organiccomputer.me
- Canonical repos: [star-centric-transport](https://github.com/IT-Help-San-Diego/star-centric-transport), [tetrasemaphore](https://github.com/IT-Help-San-Diego/tetrasemaphore), [owl-semaphore](https://github.com/IT-Help-San-Diego/owl-semaphore)

## License

The page prints no copyright, name or license line: the site owner ruled on 7 November 2026 that attribution is reached through the DOI, ORCID and GitHub records, not a footer ownership claim. No repository license file is committed yet; that choice is the owner's.

## Verify

`make check` runs `verify.sh`, the page's invariant gate: the `<style>` block's sha256 pinned in the meta Content-Security-Policy and in `infra/cloudfront/security-headers.json`, zero script tags, no inline styles, no external subresources, strict UTF-8, no em dashes, the six family links in order, the author's name only in the license line. Recompute the hash on any CSS edit; the gate prints the expected value. The page carries a DRAFT marker until Claude Science has ruled on the wording and Carey has given the final word; `STARCENTRIC_RELEASE=1 make check` makes that marker, and any HTML comment, a failure. Published set: `index.html` only (the Makefile allowlist); `verify.sh`, `Makefile`, `README.md` and `infra/` never enter the bucket. Deploy the header policy and the page in one run, then invalidate; a stale hash on either side renders the page unstyled.
