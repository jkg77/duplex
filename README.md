# Duplicate File Analyzer

A high-performance tool for identifying duplicate files across large directory structures, built with Rust.

## Features

- **Efficient Algorithm**: Uses size-based filtering before hash computation to minimize I/O operations
- **Multiple Hash Algorithms**: Supports SHA-256 and MD5 for content verification
- **Web Interface**: Modern web UI for interactive duplicate management
- **CLI Interface**: Command-line tool for scripting and automation
- **Real-time Progress**: WebSocket-based progress updates during analysis
- **Memory Efficient**: Streaming I/O and batch processing for large directories
- **Parallel Processing**: Multi-threaded analysis for optimal performance

## Installation

### Prerequisites

- Rust 1.70.0 or later
- Cargo (comes with Rust)

### Building from Source

```bash
git clone https://github.com/yourusername/duplicate-file-analyzer
cd duplicate-file-analyzer
cargo build --release
```

The binary will be available at `./target/release/duplicate-analyzer`.

## Usage

### CLI Interface

Analyze a directory:

```bash
./target/release/duplicate-analyzer analyze --directory /path/to/analyze --format text
```

Start the web server:

```bash
./target/release/duplicate-analyzer web --port 3000
```

### Web Interface

1. Start the web server: `cargo run --bin duplicate-analyzer -- web`
2. Open your browser to `http://localhost:3000`
3. Enter the target directory and start analysis
4. View results and manage duplicates through the web interface

## Development

### Prerequisites

```bash
make install-deps
```

### Common Tasks

```bash
# Build the project
make build

# Run tests
make test

# Format code
make fmt

# Run lints
make clippy

# Run all checks
make ci
```

### Project Structure

```
src/
├── lib.rs              # Library root
├── bin/main.rs         # CLI entry point
├── analysis.rs         # Analysis controller
├── discovery.rs        # File discovery engine
├── duplicate.rs        # Duplicate detection engine
├── hash.rs            # Hash computation utilities
├── models.rs          # Data models
├── progress.rs        # Progress tracking
├── report.rs          # Report generation
└── web/               # Web interface
    ├── mod.rs         # Web module root
    ├── api.rs         # Web API server
    ├── handlers.rs    # HTTP handlers
    └── websocket.rs   # WebSocket support

web/static/            # Frontend assets
├── index.html         # Main HTML page
├── styles.css         # Styles
└── app.js            # JavaScript application
```

## Algorithm

The duplicate detection follows a three-stage approach:

1. **Size Grouping**: Group files by size to eliminate obvious non-duplicates
2. **Hash Computation**: Compute content hashes only for files with matching sizes
3. **Duplicate Grouping**: Group files with identical hashes as duplicate sets

This approach minimizes expensive I/O operations while maintaining accuracy.

## Configuration

### Hash Algorithms

- **SHA-256** (default): Cryptographically secure, recommended for most use cases
- **MD5**: Faster but less secure, suitable when speed is critical

### Performance Tuning

- Adjust thread count with `--threads` option
- Use exclude patterns to skip unnecessary files
- Consider partial hash comparison for very large files

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Run lints: `make clippy`
6. Format code: `make fmt`
7. Submit a pull request

## Roadmap

- [ ] Resume interrupted analyses
- [ ] Additional hash algorithms (xxHash, BLAKE3)
- [ ] File content preview in web interface
- [ ] Batch file operations
- [ ] Export results to various formats
- [ ] Integration with cloud storage providers
