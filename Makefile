# kbouncer — make targets
#
# `make build`                  compile both binaries into ./bin/ (gitignored)
# `make install`                go install both binaries into $GOPATH/bin
# `make vet`                    go vet ./...
# `make test`                   unit tests only (always runnable, no docker)
# `make test-integration`       spin up a kind cluster + run integration tests
# `make test-integration-keep`  same but leave kind cluster running for iteration
# `make test-integration-clean` tear down the kind cluster
#
# Integration tests are build-tag gated (//go:build integration) and
# SKIP CLEANLY when KBOUNCE_TEST_KUBECONFIG isn't set — so `go test
# -tags=integration ./...` is safe even without kind installed.
#
# Required tools for `make test-integration`:
#   - docker  (kind drives docker under the hood)
#   - kind    (https://kind.sigs.k8s.io)
#
# See docs/LOCAL-TEST-INFRA.md in iam-roles for the cross-repo plan.

KBOUNCE_TEST_CLUSTER ?= kbounce-test
KBOUNCE_TEST_KUBECONFIG_PATH ?= $(CURDIR)/.kind-kubeconfig

.PHONY: build install vet test \
	test-integration test-integration-keep test-integration-clean \
	kind-up kind-down

# Local-dev build — drops binaries into ./bin/ which is gitignored. NEVER
# commit the contents of bin/. The canonical install path for end users
# is `go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest` per
# README; this target exists for source-tree iteration only.
build:
	@mkdir -p bin
	go build -o bin/kbounce ./cmd/kbounce
	go build -o bin/kbouncer ./cmd/kbouncer

# Equivalent of the canonical end-user install — drops the binary into
# $GOPATH/bin (or $HOME/go/bin). Use this when you want the locally-
# built binary on your PATH without committing ./bin/.
install:
	go install ./cmd/kbounce
	go install ./cmd/kbouncer

vet:
	go vet ./...

test:
	go test ./...

# Full integration run: create cluster, write a kubeconfig the test
# process can read, run the build-tagged suite, tear cluster down.
# A trap is used so the cluster is removed even if `go test` fails.
test-integration: kind-up
	@trap '$(MAKE) kind-down' EXIT; \
	KBOUNCE_TEST_KUBECONFIG=$(KBOUNCE_TEST_KUBECONFIG_PATH) \
	go test -tags=integration -timeout 5m ./internal/proxy/... -v

# Same as test-integration but does NOT tear the cluster down. Use
# this in the inner iteration loop — repeated `make test-integration-keep`
# is dramatically faster than spinning kind on every run (~20s vs ~5s).
test-integration-keep:
	@if ! kind get clusters 2>/dev/null | grep -q '^$(KBOUNCE_TEST_CLUSTER)$$'; then \
		$(MAKE) kind-up; \
	fi
	KBOUNCE_TEST_KUBECONFIG=$(KBOUNCE_TEST_KUBECONFIG_PATH) \
	go test -tags=integration -timeout 5m ./internal/proxy/... -v

test-integration-clean:
	$(MAKE) kind-down

# Internal — bring a kind cluster up + export its kubeconfig to a path
# the test process can read. Uses --internal=false so the URL is the
# host-reachable docker-published port (the in-cluster URL won't work
# from the test process running on the host).
kind-up:
	@command -v kind >/dev/null 2>&1 || { \
		echo "kind not installed — install from https://kind.sigs.k8s.io"; \
		exit 1; \
	}
	@if ! kind get clusters 2>/dev/null | grep -q '^$(KBOUNCE_TEST_CLUSTER)$$'; then \
		echo "creating kind cluster $(KBOUNCE_TEST_CLUSTER)..."; \
		kind create cluster --name $(KBOUNCE_TEST_CLUSTER) --wait 90s; \
	else \
		echo "kind cluster $(KBOUNCE_TEST_CLUSTER) already exists; reusing"; \
	fi
	@kind get kubeconfig --name $(KBOUNCE_TEST_CLUSTER) --internal=false \
		> $(KBOUNCE_TEST_KUBECONFIG_PATH)
	@echo "kubeconfig written to $(KBOUNCE_TEST_KUBECONFIG_PATH)"

kind-down:
	@if kind get clusters 2>/dev/null | grep -q '^$(KBOUNCE_TEST_CLUSTER)$$'; then \
		echo "deleting kind cluster $(KBOUNCE_TEST_CLUSTER)..."; \
		kind delete cluster --name $(KBOUNCE_TEST_CLUSTER); \
	fi
	@rm -f $(KBOUNCE_TEST_KUBECONFIG_PATH)
