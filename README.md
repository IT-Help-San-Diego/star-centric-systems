# star-centric-systems

**Star-Centric Systems: the roof.** Family site for starcentric.systems: keystone Star-Centric Transport, method pillars, instruments.

## Status

- **Page build:** Claude Code lane (design and build): a single self-contained `index.html`, zero JavaScript, the family pattern.
- **Infrastructure:** Hermes lane (private S3 bucket, CloudFront with the response-headers policy in `infra/cloudfront/`, DNS).
- **Wording:** ruled by the Claude Science lane; the site owner gave the final word on 7 November 2026.
- **Review:** prepared through human-led, multi-agent review; what each lane did is recorded in the pull request that brought the page in.

## Family

- it-help.tech | intellectualresistance.com | calibrationscope.com | resolutionscope.com | tetrasemaphore.systems | organiccomputer.me
- Canonical repos: [star-centric-transport](https://github.com/IT-Help-San-Diego/star-centric-transport), [tetrasemaphore](https://github.com/IT-Help-San-Diego/tetrasemaphore), [owl-semaphore](https://github.com/IT-Help-San-Diego/owl-semaphore)

## License

`LICENSE` carries Creative Commons Attribution 4.0 International (CC BY 4.0), the family default, for this repository's content; it is the same file the Tetrasemaphore repository carries. The page itself prints no copyright, name or license line: the site owner ruled on 7 November 2026 that attribution is reached through the DOI, ORCID and GitHub records, not a footer ownership claim. A separate code license is not declared.

## Verify

`make check` runs `verify.sh`, the page's invariant gate: the `<style>` block's sha256 pinned in the meta Content-Security-Policy and in `infra/cloudfront/security-headers.json`, zero script tags, no inline styles, no external subresources, strict UTF-8, no em dashes, the six family links in order, no personal name or copyright line. Recompute the hash on any CSS edit; the gate prints the expected value. `make release` runs the same gate with `STARCENTRIC_RELEASE=1`, which makes a draft marker, or any HTML comment, a failure; the released page carries none. Published set: `index.html` only (the Makefile allowlist); `verify.sh`, `Makefile`, `README.md` and `infra/` never enter the bucket. Deploy the header policy and the page in one run, then invalidate; a stale hash on either side renders the page unstyled.
