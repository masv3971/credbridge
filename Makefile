# ==============================================================================
# Configuration Variables
# ==============================================================================

NAME                    := credbridge
VERSION                 ?= local
CURRENT_BRANCH          := $(shell git rev-parse --abbrev-ref HEAD)

# Docker Configuration
REGISTRY                := docker.sunet.se/iam_vc
DOCKER_TAG              := $(REGISTRY)/$(NAME):$(VERSION)

# ==============================================================================
# Phony Targets Declaration
# ==============================================================================

.PHONY: docker-build docker-push start stop restart release check_current_branch gosec staticcheck vulncheck deadcode fmt vscode test test-coverage tidy lint install-gh

# ==============================================================================
# Docker Build
# ==============================================================================

# ==============================================================================
# Development Environment
# ==============================================================================

vscode: install-gh ## Set up VS Code development environment
	$(info Installing go packages)
	go install github.com/securego/gosec/v2/cmd/gosec@latest && \
	go install golang.org/x/vuln/cmd/govulncheck@latest && \
	go install honnef.co/go/tools/cmd/staticcheck@latest && \
	go install golang.org/x/tools/cmd/deadcode@latest && \
	go install mvdan.cc/gofumpt@latest

install-gh: ## Install the GitHub CLI (gh) if it is not already present
	@if command -v gh >/dev/null 2>&1; then \
		echo "gh already installed: $$(gh --version | head -n1)"; \
	else \
		echo "Installing GitHub CLI (gh)..."; \
		type -p curl >/dev/null || sudo apt-get install -y curl; \
		curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
			sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg; \
		sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg; \
		echo "deb [arch=$$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | \
			sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null; \
		sudo apt-get update; \
		sudo apt-get install -y gh; \
		echo "gh installed: $$(gh --version | head -n1)"; \
	fi

# ==============================================================================
# Release Management
# ==============================================================================

BUMP                    ?= patch
FORCE                   ?=

check_current_branch:
	$(info Current branch: $(CURRENT_BRANCH))
ifeq ($(CURRENT_BRANCH),main)
	$(info On main branch)
else
ifneq ($(FORCE),true)
	$(error Not on main branch — use FORCE=true to override)
else
	$(warning Not on main branch — continuing because FORCE=true)
endif
endif

release: check_current_branch ## Create and push a git tag (BUMP=major|minor|patch)
	@echo "$(BUMP)" | grep -qE '^(major|minor|patch)$$' || \
		{ echo "Error: BUMP must be major, minor, or patch (got: $(BUMP))"; exit 1; }
	@if [ "$(FORCE)" != "true" ] && ! git diff --quiet HEAD 2>/dev/null; then \
		echo "Error: working tree is dirty — commit or stash changes first (use FORCE=true to override)"; exit 1; \
	fi
	@LATEST=$$(git tag -l "v*" --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
	if [ -z "$$LATEST" ]; then \
		echo "No existing version tags found, starting at v0.0.0"; \
		LATEST="v0.0.0"; \
	fi; \
	CURRENT=$$(echo "$$LATEST" | sed 's/^v//'); \
	MAJOR=$$(echo "$$CURRENT" | cut -d. -f1); \
	MINOR=$$(echo "$$CURRENT" | cut -d. -f2); \
	PATCH=$$(echo "$$CURRENT" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0 ;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0 ;; \
		patch) PATCH=$$((PATCH + 1)) ;; \
	esac; \
	NEW_TAG="v$${MAJOR}.$${MINOR}.$${PATCH}"; \
	echo ""; \
	echo "Bumping $$LATEST -> $$NEW_TAG ($(BUMP))"; \
	echo ""; \
	git tag -a "$$NEW_TAG" -m "Release $$NEW_TAG"; \
	git push origin "$$NEW_TAG"; \
	echo ""; \
	echo "==> Release $$NEW_TAG created and pushed"; \
	echo ""

# ==============================================================================
# Code Quality & Security
# ==============================================================================

gosec: ## Run gosec security scanner
	gosec -color -tests ./...

staticcheck: ## Run staticcheck linter
	staticcheck ./...

vulncheck: ## Run vulnerability checker
	govulncheck -scan package ./...

deadcode: ## Report unreachable functions (uses tests as entry points)
	deadcode -test ./...

fmt: ## Format code with gofumpt
	gofumpt -w .

test: ## Run unit tests + examples
	go test -count=1 ./...

test-coverage: ## Run tests and emit coverage.out + coverage.html
	go test -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "HTML report: coverage.html"

tidy: ## Sync go.mod / go.sum
	go mod tidy

lint: staticcheck vulncheck gosec deadcode ## Run all quality gates