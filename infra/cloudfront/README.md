# CloudFront response-headers policy

`security-headers.json` is the response-headers policy for starcentric.systems: the tetrasemaphore.systems policy with its own name, a comment within CloudFront's 128-character limit, and one `style-src` hash, the sha256 of the bytes strictly between `<style>` and `</style>` in `index.html`. `verify.sh` checks that the file equals the family policy with that hash. Apply the policy before the first page upload, and on any CSS edit update the page and the policy in one run, then invalidate; a stale hash on either side renders the page unstyled. The infrastructure lane owns applying it.

The meta policy on `index.html` and `404.html` is deliberately a subset of this one. It leaves out `frame-ancestors`, which browsers ignore when a policy arrives in a meta element and report in the console on every load. This header is where `frame-ancestors` takes effect, on every path. Do not add it back to the meta policy; `verify.sh` fails if it appears there.
