.PHONY: check test verify release deploy-dry-run deploy

# Set by the infrastructure lane when the bucket and distribution exist. Left empty here on purpose.
BUCKET ?=
REGION ?= us-east-1
DIST_ID ?=

# The published set is exactly this. Everything else in the repository stays out of the bucket.
ALLOWLIST := \
	--exclude "*" \
	--include "index.html"

check:
	@./verify.sh

test: check

verify: check

release:
	@STARCENTRIC_RELEASE=1 ./verify.sh

deploy-dry-run: check
	@test -n "$(BUCKET)" || { echo "BUCKET is unset: the infrastructure lane sets it when the bucket exists"; exit 2; }
	aws s3 sync . $(BUCKET) --region $(REGION) $(ALLOWLIST) --dryrun

deploy: check
	@test -n "$(BUCKET)" || { echo "BUCKET is unset: the infrastructure lane sets it when the bucket exists"; exit 2; }
	@test -n "$(DIST_ID)" || { echo "DIST_ID is unset: the infrastructure lane sets it when the distribution exists"; exit 2; }
	aws s3 sync . $(BUCKET) --region $(REGION) $(ALLOWLIST)
	aws s3 cp index.html "$(BUCKET)/index.html" --region $(REGION) --content-type "text/html; charset=utf-8" --cache-control "no-cache"
	aws cloudfront create-invalidation --distribution-id $(DIST_ID) --paths "/*"
