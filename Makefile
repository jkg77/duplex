# Duplicate File Analyzer - Development Makefile

.PHONY: help build test check fmt clippy clean run-cli run-web install-deps

# Default target
help:
	@echo "Available targets:"
	@echo "  build       - Build the project"
	@echo "  test        - Run all tests"
	@echo "  check       - Run cargo check"
	@echo "  fmt         - Format code with rustfmt"
	@echo "  clippy      - Run clippy lints"
	@echo "  clean       - Clean build artifacts"
	@echo "  run-cli     - Run CLI version"
	@echo "  run-web     - Run web server"
	@echo "  install-deps- Install development dependencies"

# Build the project
build:
	cargo build

# Build for release
build-release:
	cargo build --release

# Run all tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Run property-based tests specifically
test-prop:
	cargo test --test '*' -- --nocapture

# Run cargo check
check:
	cargo check

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt -- --check

# Run clippy
clippy:
	cargo clippy -- -D warnings

# Run clippy with all targets
clippy-all:
	cargo clippy --all-targets --all-features -- -D warnings

# Clean build artifacts
clean:
	cargo clean

# Run CLI version (example)
run-cli:
	cargo run --bin duplicate-analyzer -- analyze --directory ./test-data --format text

# Run web server
run-web:
	cargo run --bin duplicate-analyzer -- web --port 3000

# Install development dependencies
install-deps:
	rustup component add rustfmt clippy

# Run all checks (CI-like)
ci: fmt-check clippy-all test

# Development workflow
dev: fmt clippy test

# Watch for changes and run tests
watch:
	cargo watch -x test

# Generate documentation
docs:
	cargo doc --open

# Benchmark tests
bench:
	cargo bench