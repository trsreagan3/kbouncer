# kbouncer — make targets
#
# `make build`                  compile both binaries (kbounce + legacy kbouncer)
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

.PHONY: build vet test \
	test-integration test-integration-keep test-integration-clean \
	kind-up kind-down

build:
	go build ./...

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
