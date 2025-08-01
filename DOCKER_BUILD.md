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

### Quick Build

To create a full release (git tag, Docker image, and Ansible Galaxy archive):

```bash
make build
```

This will:
1. Create a git tag `release-X.Y.Z` (based on VERSION file)
2. Build Docker images tagged as `khmarochos/pki:X.Y.Z` and `khmarochos/pki:latest`
3. Build the Ansible Galaxy collection archive `khmarochos-pki-X.Y.Z.tar.gz`

### Individual Build Steps

You can also run individual build steps:

```bash
# Check current version
make check-version

# Create git tag only
make tag-release

# Build Docker image only
make build-docker

# Build Ansible Galaxy archive only
make build-galaxy

# Clean generated files
make clean
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