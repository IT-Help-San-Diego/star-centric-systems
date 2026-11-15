.PHONY: check test verify release deploy-dry-run deploy

# Set by the infrastructure lane when the bucket and distribution exist. Left empty here on purpose.
BUCKET ?=
REGION ?= us-east-1
DIST_ID ?=

# The published set is exactly these four files. Everything else in the repository stays out of the bucket.
# deploy uploads the four files by name; the allowlist serves deploy-dry-run, which previews the same set.
ALLOWLIST := \
	--exclude "*" \
	--include "index.html" \
	--include "404.html" \
	--include "robots.txt" \
	--include ".well-known/security.txt"

check:
	@./verify.sh

test: check

verify: check

release:
	@STARCENTRIC_RELEASE=1 ./verify.sh

deploy-dry-run: release
	@test -n "$(BUCKET)" || { echo "BUCKET is unset: the infrastructure lane sets it when the bucket exists"; exit 2; }
	@case "$(BUCKET)" in */) echo "BUCKET must not end with a slash"; exit 2;; esac
	aws s3 sync . $(BUCKET) --region $(REGION) $(ALLOWLIST) --dryrun

deploy: release
	@test -n "$(BUCKET)" || { echo "BUCKET is unset: the infrastructure lane sets it when the bucket exists"; exit 2; }
	@test -n "$(DIST_ID)" || { echo "DIST_ID is unset: the infrastructure lane sets it when the distribution exists"; exit 2; }
	@case "$(BUCKET)" in */) echo "BUCKET must not end with a slash"; exit 2;; esac
	aws s3 cp index.html "$(BUCKET)/index.html" --region $(REGION) --content-type "text/html; charset=utf-8" --cache-control "no-cache"
	aws s3 cp 404.html "$(BUCKET)/404.html" --region $(REGION) --content-type "text/html; charset=utf-8" --cache-control "no-cache"
	aws s3 cp robots.txt "$(BUCKET)/robots.txt" --region $(REGION) --content-type "text/plain; charset=utf-8" --cache-control "max-age=300"
	aws s3 cp .well-known/security.txt "$(BUCKET)/.well-known/security.txt" --region $(REGION) --content-type "text/plain; charset=utf-8" --cache-control "max-age=300"
	aws cloudfront create-invalidation --distribution-id $(DIST_ID) --paths "/*"
