# Makefile for khmarochos.pki project
#
# This Makefile automates common development and release tasks
#
# Usage:
#   make build     - Create a new release (tag, Docker image, Ansible Galaxy archive)
#   make clean     - Clean generated files
#   make help      - Show this help message

# Default shell
SHELL := /bin/bash

# Get version from VERSION file
VERSION := $(shell cat VERSION)

# Docker configuration
DOCKER_REGISTRY := khmarochos
DOCKER_IMAGE := pki
DOCKER_TAG := $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(VERSION)
DOCKER_TAG_LATEST := $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest

# Ansible Galaxy configuration
GALAXY_NAMESPACE := khmarochos
GALAXY_NAME := pki
GALAXY_BUILD_DIR := collections/ansible_collections/$(GALAXY_NAMESPACE)/$(GALAXY_NAME)
GALAXY_ARCHIVE := $(GALAXY_NAMESPACE)-$(GALAXY_NAME)-$(VERSION).tar.gz

# Git configuration
GIT_TAG := release-$(VERSION)

.PHONY: help
help: ## Show this help message
	@echo "khmarochos.pki Makefile"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

.PHONY: check-version
check-version: ## Check current version
	@echo "Current version: $(VERSION)"

.PHONY: check-prerequisites
check-prerequisites: ## Check required tools
	@echo "Checking prerequisites..."
	@command -v git >/dev/null 2>&1 || { echo "Error: git is not installed"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed"; exit 1; }
	@command -v ansible-galaxy >/dev/null 2>&1 || { echo "Error: ansible-galaxy is not installed"; exit 1; }
	@echo "All prerequisites are installed"

.PHONY: check-git-status
check-git-status: ## Check if git working directory is clean
	@echo "Checking git status..."
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Warning: Working directory has uncommitted changes"; \
		git status --short; \
		echo ""; \
		read -p "Continue anyway? [y/N] " -n 1 -r; \
		echo ""; \
		if [[ ! $$REPLY =~ ^[Yy]$$ ]]; then \
			echo "Aborted"; \
			exit 1; \
		fi \
	else \
		echo "Working directory is clean"; \
	fi

.PHONY: init-submodules
init-submodules: ## Initialize git submodules
	@echo "Initializing git submodules..."
	@git submodule update --init --recursive
	@echo "Submodules initialized"

.PHONY: tag-release
tag-release: check-git-status ## Create git tag for release
	@echo "Creating git tag $(GIT_TAG)..."
	@if git rev-parse $(GIT_TAG) >/dev/null 2>&1; then \
		echo "Warning: Tag $(GIT_TAG) already exists"; \
		read -p "Delete and recreate tag? [y/N] " -n 1 -r; \
		echo ""; \
		if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
			git tag -d $(GIT_TAG); \
			git push origin --delete $(GIT_TAG) 2>/dev/null || true; \
		else \
			echo "Aborted"; \
			exit 1; \
		fi \
	fi
	@git tag -a $(GIT_TAG) -m "Release version $(VERSION)"
	@echo "Git tag $(GIT_TAG) created"
	@echo "Note: Run 'git push origin $(GIT_TAG)' to push the tag to remote"

.PHONY: build-docker
build-docker: init-submodules ## Build Docker image
	@echo "Building Docker image $(DOCKER_TAG)..."
	@docker build -t $(DOCKER_TAG) -t $(DOCKER_TAG_LATEST) .
	@echo "Docker image built successfully"
	@echo "Images created:"
	@echo "  - $(DOCKER_TAG)"
	@echo "  - $(DOCKER_TAG_LATEST)"

.PHONY: build-galaxy
build-galaxy: ## Build Ansible Galaxy collection archive
	@echo "Building Ansible Galaxy collection..."
	@cd $(GALAXY_BUILD_DIR) && ansible-galaxy collection build --force
	@if [ -f "$(GALAXY_BUILD_DIR)/$(GALAXY_ARCHIVE)" ]; then \
		mv $(GALAXY_BUILD_DIR)/$(GALAXY_ARCHIVE) .; \
		echo "Galaxy collection built: $(GALAXY_ARCHIVE)"; \
	else \
		echo "Error: Failed to build Galaxy collection"; \
		exit 1; \
	fi

.PHONY: build
build: check-prerequisites check-version tag-release build-docker build-galaxy ## Build release (tag, Docker, Galaxy)
	@echo ""
	@echo "Build completed successfully!"
	@echo ""
	@echo "Summary:"
	@echo "  - Git tag:        $(GIT_TAG)"
	@echo "  - Docker images:  $(DOCKER_TAG), $(DOCKER_TAG_LATEST)"
	@echo "  - Galaxy archive: $(GALAXY_ARCHIVE)"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Push everything:  make push"
	@echo "  2. Publish Galaxy:   make publish-galaxy"

.PHONY: push-git
push-git: ## Push git tag to remote
	@echo "Pushing git tag $(GIT_TAG) to remote..."
	@if ! git rev-parse $(GIT_TAG) >/dev/null 2>&1; then \
		echo "Error: Git tag $(GIT_TAG) does not exist locally"; \
		echo "Run 'make tag-release' or 'make build' first"; \
		exit 1; \
	fi
	@git push origin $(GIT_TAG)
	@echo "Git tag $(GIT_TAG) pushed successfully"

.PHONY: push-docker
push-docker: ## Push Docker images to registry
	@echo "Pushing Docker images to registry..."
	@if ! docker image inspect $(DOCKER_TAG) >/dev/null 2>&1; then \
		echo "Error: Docker image $(DOCKER_TAG) does not exist locally"; \
		echo "Run 'make build-docker' or 'make build' first"; \
		exit 1; \
	fi
	@echo "Pushing $(DOCKER_TAG)..."
	@docker push $(DOCKER_TAG)
	@echo "Pushing $(DOCKER_TAG_LATEST)..."
	@docker push $(DOCKER_TAG_LATEST)
	@echo "Docker images pushed successfully"

.PHONY: push
push: push-git push-docker ## Push git tag and Docker images
	@echo ""
	@echo "Push completed successfully!"
	@echo ""
	@echo "Pushed:"
	@echo "  - Git tag:        $(GIT_TAG)"
	@echo "  - Docker images:  $(DOCKER_TAG), $(DOCKER_TAG_LATEST)"
	@echo ""
	@echo "Next step:"
	@echo "  - Publish Galaxy:   make publish-galaxy"

.PHONY: publish-galaxy
publish-galaxy: ## Publish Ansible Galaxy collection
	@echo "Publishing Ansible Galaxy collection..."
	@if [ ! -f "$(GALAXY_ARCHIVE)" ]; then \
		echo "Error: Galaxy archive $(GALAXY_ARCHIVE) not found"; \
		echo "Run 'make build-galaxy' or 'make build' first"; \
		exit 1; \
	fi
	@ansible-galaxy collection publish $(GALAXY_ARCHIVE)
	@echo "Galaxy collection $(GALAXY_ARCHIVE) published successfully"

.PHONY: release
release: build push publish-galaxy ## Complete release workflow (build, push, publish)
	@echo ""
	@echo "Release $(VERSION) completed successfully!"
	@echo ""
	@echo "Summary:"
	@echo "  - Git tag $(GIT_TAG) created and pushed"
	@echo "  - Docker images $(DOCKER_TAG) and $(DOCKER_TAG_LATEST) built and pushed"
	@echo "  - Galaxy collection $(GALAXY_ARCHIVE) built and published"

.PHONY: clean
clean: ## Clean generated files
	@echo "Cleaning generated files..."
	@rm -f $(GALAXY_NAMESPACE)-$(GALAXY_NAME)-*.tar.gz
	@rm -f $(GALAXY_BUILD_DIR)/$(GALAXY_NAMESPACE)-$(GALAXY_NAME)-*.tar.gz
	@echo "Clean completed"

.PHONY: docker-run
docker-run: ## Run Docker container with example configuration
	@echo "Running Docker container..."
	@docker run --rm -it \
		-v "$${PWD}/vars:/app/vars:ro" \
		-v "$${PWD}/pki:/app/pki" \
		$(DOCKER_TAG_LATEST)

.PHONY: docker-shell
docker-shell: ## Open shell in Docker container
	@echo "Opening shell in Docker container..."
	@docker run --rm -it \
		-v "$${PWD}/vars:/app/vars:ro" \
		-v "$${PWD}/pki:/app/pki" \
		--entrypoint /bin/bash \
		$(DOCKER_TAG_LATEST)

.PHONY: test
test: ## Run unit tests
	@echo "Running unit tests..."
	@cd collections/ansible_collections/$(GALAXY_NAMESPACE)/$(GALAXY_NAME) && \
		python -m pytest tests/unit/ -v

.PHONY: lint
lint: ## Run linters
	@echo "Running linters..."
	@echo "Note: Add your linting commands here"

.PHONY: version-patch
version-patch: ## Increment patch version (0.0.X)
	@current_version=$$(cat VERSION); \
	new_version=$$(echo $$current_version | awk -F. '{$$NF = $$NF + 1;} 1' | sed 's/ /./g'); \
	echo "Incrementing version from $$current_version to $$new_version"; \
	echo $$new_version > VERSION; \
	sed -i "s/version: $$current_version/version: $$new_version/" $(GALAXY_BUILD_DIR)/galaxy.yml; \
	sed -i "s/version=\"$$current_version\"/version=\"$$new_version\"/" Dockerfile; \
	echo "Version updated to $$new_version"; \
	echo "Don't forget to update CHANGELOG.md!"

.PHONY: version-minor
version-minor: ## Increment minor version (0.X.0)
	@current_version=$$(cat VERSION); \
	new_version=$$(echo $$current_version | awk -F. '{$$2 = $$2 + 1; $$3 = 0;} 1' | sed 's/ /./g'); \
	echo "Incrementing version from $$current_version to $$new_version"; \
	echo $$new_version > VERSION; \
	sed -i "s/version: $$current_version/version: $$new_version/" $(GALAXY_BUILD_DIR)/galaxy.yml; \
	sed -i "s/version=\"$$current_version\"/version=\"$$new_version\"/" Dockerfile; \
	echo "Version updated to $$new_version"; \
	echo "Don't forget to update CHANGELOG.md!"

.PHONY: version-major
version-major: ## Increment major version (X.0.0)
	@current_version=$$(cat VERSION); \
	new_version=$$(echo $$current_version | awk -F. '{$$1 = $$1 + 1; $$2 = 0; $$3 = 0;} 1' | sed 's/ /./g'); \
	echo "Incrementing version from $$current_version to $$new_version"; \
	echo $$new_version > VERSION; \
	sed -i "s/version: $$current_version/version: $$new_version/" $(GALAXY_BUILD_DIR)/galaxy.yml; \
	sed -i "s/version=\"$$current_version\"/version=\"$$new_version\"/" Dockerfile; \
	echo "Version updated to $$new_version"; \
	echo "Don't forget to update CHANGELOG.md!"

# Default target
.DEFAULT_GOAL := help