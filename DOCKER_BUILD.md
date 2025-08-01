# Build Instructions

## Prerequisites

This project uses git submodules for the bash-helpers library. Before building the Docker image, you must initialize the submodules:

```bash
git submodule update --init --recursive
```

## Building the Image

After initializing submodules, build the Docker image:

```bash
docker build -t khmarochos/pki:latest .
```

## Using docker-compose

If using docker-compose, the same submodule initialization is required:

```bash
# Initialize submodules first
git submodule update --init --recursive

# Then use docker-compose
docker-compose build
docker-compose up
```

## Automated CI/CD

For CI/CD pipelines, ensure your pipeline includes the submodule initialization step:

### GitHub Actions example:
```yaml
- uses: actions/checkout@v3
  with:
    submodules: recursive
```

### GitLab CI example:
```yaml
variables:
  GIT_SUBMODULE_STRATEGY: recursive
```

### Jenkins example:
```groovy
checkout scm: [
  $class: 'GitSCM',
  submoduleCfg: [
    $class: 'SubmoduleOption',
    recursiveSubmodules: true
  ]
]
```

## Using the Makefile

This project includes a Makefile that automates the build process:

### Complete Release Workflow

To do a complete release (build, push, and publish everything):

```bash
make release
```

This will:
1. Create a git tag `release-X.Y.Z` (based on VERSION file)
2. Build Docker images tagged as `khmarochos/pki:X.Y.Z` and `khmarochos/pki:latest`
3. Build the Ansible Galaxy collection archive `khmarochos-pki-X.Y.Z.tar.gz`
4. Push the git tag to remote repository
5. Push Docker images to registry
6. Publish the Galaxy collection to Ansible Galaxy

### Build Only

To just build without pushing:

```bash
make build
```

### Individual Steps

You can also run individual steps:

```bash
# Build steps
make build-docker        # Build Docker images only
make build-galaxy        # Build Galaxy archive only
make tag-release         # Create git tag only

# Push steps  
make push-git           # Push git tag only
make push-docker        # Push Docker images only
make push               # Push both git tag and Docker images
make publish-galaxy     # Publish Galaxy collection only

# Utility
make check-version      # Show current version
make clean             # Clean generated files
```

### Version Management

The Makefile includes helpers for version bumping:

```bash
# Increment patch version (0.0.X)
make version-patch

# Increment minor version (0.X.0)
make version-minor

# Increment major version (X.0.0)
make version-major
```

After incrementing the version, don't forget to update the CHANGELOG.md files!

### Docker Helpers

```bash
# Run the container with example configuration
make docker-run

# Open a shell in the container for debugging
make docker-shell
```

### Development

```bash
# Run unit tests
make test

# Initialize git submodules
make init-submodules

# Show all available targets
make help
```