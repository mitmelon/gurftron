# Gurftron Engine — Native Antivirus & Local LLM

Gurftron Engine is a compact, high-performance native host written in Rust that provides:

- Fast ClamAV-based file scanning (async)
- A native messaging bridge for browser extensions (Chrome/Brave/Edge/Firefox)
- Optional local LLM support (llama.cpp via the `llama_cpp_2` bindings) used for threat reasoning and natural-language summaries

---

## Quick highlights

- Native messaging actions supported (JSON over length-prefixed stdin/stdout):
  - `scan` — start an asynchronous file scan. payload: `{ "action": "scan", "path": "C:\\path\\to\\file" }` → returns `{ scan_id, file_id }`
  - `check_scan` — query scan result. payload: `{ "action": "check_scan", "scan_id": "..." }`
  - `get_file_hash` — compute SHA-256 of a local file. payload: `{ "action": "get_file_hash", "path": "..." }`
  - `ping` — health check. payload: `{ "action": "ping" }`
  - `chat_completion` — run the local LLM completion. payload: `{ "action":"chat_completion", "messages": [{"role":"user","content":"..."}], "max_tokens":512 }`
  - `model_info` — returns current model metadata if LLM initialized.

- Scan results are persisted in a local SQLite DB (scan history and caching by file hash).
- The engine communicates with ClamAV over TCP (default port 3310) using the INSTREAM protocol.

---

## Requirements (important)

1. Rust toolchain (rustc + cargo) — install via https://rustup.rs/
2. Native toolchain required for the LLM/backends:
   - CMake — used to build native C/C++ dependencies (e.g. llama.cpp bindings). Download: https://cmake.org/download/
   - LLVM / Clang — required by some crates and native backends (ensure clang is on PATH). Download: https://github.com/llvm/llvm-project/releases

If `cargo build` fails with missing C symbols, linker errors, or failures while compiling native bindings, install CMake and LLVM and ensure they are available on your PATH before building.

Optional runtime tools:
- ClamAV (`clamd` + `freshclam`) for scanning (engine will attempt to auto-install on Windows when run).

---

## Build & Run

Development build:

```powershell
cd program\gurftron_engine
cargo build
```

Release build:

```powershell
cargo build --release
```

Run (first-run will attempt ClamAV setup and register native messaging manifests):

```powershell
# development
cargo run

# release
cargo run --release
```

Executable paths:
- debug: `target/debug/gurftron_engine` (Windows: `gurftron_engine.exe`)
- release: `target/release/gurftron_engine`

---

## Local LLM (optional)

The engine embeds an optional local LLM layer using the `llama_cpp_2` bindings. The LLM is initialized on demand and used only for `chat_completion` and `model_info` actions.

Behavior details:
- On initialization the engine will download a GGUF model into a local cache directory (default: platform data dir + `gurftron_models`). Model downloads can be large.
- The engine auto-selects a model based on available RAM. Models included in code: TinyLlama-1.1B, Phi-2-2.7B, Mistral-7B-Instruct, Llama-3-8B-Instruct.
- The LLM backend requires native build tooling (CMake + LLVM) because it links native C/C++ libraries.

Chat completion request example:

```json
{
  "action": "chat_completion",
  "messages": [
    {"role": "system", "content": "You are a security assistant."},
    {"role": "user",   "content": "Summarize this evidence and produce a concise threat summary."}
  ],
  "max_tokens": 256
}
```

Response: structured completion with `id`, `model`, `choices` and `usage` fields.

If LLM initialization fails, the engine logs a warning and continues to accept non-LLM actions.

---

## Native messaging protocol (details)

Communication uses a 4-byte little-endian length prefix followed by UTF-8 JSON payloads on stdin/stdout.

Examples of payload shapes and expected responses are implemented in `src/main.rs` (see `handle_native_message`). All responses include at least `result` and `details` fields.

Scan request example:

```json
{ "action": "scan", "path": "C:\\path\\to\\file.exe" }
```

LLM completion example:

```json
{ "action": "chat_completion", "messages": [{"role":"user","content":"Explain X"}], "max_tokens": 512 }
```

---

## Troubleshooting

- `cargo build` errors that mention `clang`, `cc`, or missing libraries usually mean CMake/LLVM are missing — install them and retry.
- If `clamd` can't be reached on port 3310, ensure `clamd` is running and configured to listen on TCP 127.0.0.1:3310.
- Model download failures: check network, disk space, and permissions for the model cache dir.

Quick checks (PowerShell):

```powershell
# clamd
where clamd

# cmake
where cmake

# clang
where clang
```

---

## Testing

Ping test:

```powershell
echo '{"action":"ping"}' | .\target\release\gurftron_engine.exe
```

Manual LLM test (requires model): call `chat_completion` with a properly length-prefixed message (helper script recommended).

If you'd like, I can add a tiny helper script to wrap JSON messages with the 4-byte length prefix to make manual testing from PowerShell or bash easy.

---

## Developer notes

- Scan records and caching live in SQLite (user local app data dir).
- LLM completions are exposed via structured responses (`choices`, `usage`).

---

License: see repository root.
# Gurftron Security Engine

A high-performance antivirus scanning engine written in Rust that bridges browser extensions with ClamAV for real-time file scanning. The engine provides native messaging capabilities, async scanning with progress tracking, and intelligent caching through SQLite.

## What Does It Do?

Gurftron Engine acts as a native host that allows browser extensions to scan files on your local system using ClamAV antivirus. It provides:

- **Real-time file scanning** through ClamAV integration
- **Native messaging** support for Chrome, Edge, Brave, and Firefox extensions
- **Async scanning** with non-blocking operations and progress tracking
- **Smart caching** using SQLite to avoid rescanning identical files
- **File hashing** (SHA-256) for integrity verification
- **Auto-installation** of ClamAV and virus definitions
- **Cross-platform** support for Windows, macOS, and Linux

When a browser extension needs to scan a file, it communicates with this engine through native messaging. The engine manages ClamAV daemons, handles scan requests, tracks scan progress, and returns results back to the browser.

## Key Features

### Native Messaging Integration
Registers itself with major browsers to enable secure communication between browser extensions and the local antivirus engine. Supports:
- Google Chrome
- Microsoft Edge
- Brave Browser
- Mozilla Firefox

### Async Scanning Architecture
- Non-blocking file scans that return scan IDs immediately
- Poll scan status using unique scan IDs
- Multiple concurrent scans supported
- Fast chunked file transfers (64KB chunks)

### Intelligent Caching
- SQLite database stores scan results with SHA-256 file hashes
- Instant results for previously scanned files
- Tracks scan history with timestamps
- Reduces unnecessary rescanning

### Daemon Management
- Automatically starts ClamAV daemon if not running
- Updates virus definitions via freshclam
- Monitors daemon health
- Cross-platform daemon handling

### Security & Performance
- Connection timeouts and read/write limits
- Streaming file transfers to reduce memory usage
- Progress bars for downloads and large operations
- TCP optimization for faster scanning

## Architecture

```
Browser Extension
       ↓ (Native Messaging)
Gurftron Engine (Rust)
       ↓ (TCP Socket)
ClamAV Daemon (clamd)
       ↓
Virus Definitions
```

The engine receives JSON messages via stdin, processes scan requests, communicates with ClamAV over TCP (port 3310), stores results in SQLite, and returns JSON responses via stdout.

## Local LLM (llama.cpp) support

Starting with v2.2 the engine can optionally initialize a local LLM (via the `llama_cpp_2` bindings) to assist with advanced threat reasoning, artifact classification, and natural-language summaries. The local LLM is embedded in the native engine and will be initialized on demand.

Key points:
- The LLM subsystem downloads model GGUF files from configured Hugging Face repositories into `{model_dir}` (default: `~/.cache/gurftron/models/`).
- Available model presets (auto-detected by RAM): TinyLlama-1.1B, Phi-2-2.7B, Mistral-7B-Instruct, Llama-3-8B-Instruct. The engine selects the largest model that fits available RAM.
- The LLM uses `llama_cpp_2` and a native backend that requires platform toolchain support (CMake + LLVM). See the Prerequisites above.
- The LLM produces structured completions as JSON-style objects used by the rest of the engine. The engine exposes limited LLM completions via native messaging (use action `llm_complete` with messages payload).

Initialize the LLM (manual):

```bash
# From the engine directory
RUST_LOG=info cargo run --release -- --init-llm
```

Or let the engine auto-initialize on first request; the initial model download can be large and may take significant time.

Runtime notes:
- Ensure you have enough RAM for the selected model (the engine will select a model based on available RAM).
- Downloads are performed with resumable streams and show a progress bar.
- If you need to prevent LLM initialization, set the environment variable `GURFTRON_DISABLE_LLM=1` before running the engine.


## Building the Program

### Prerequisites

You'll need to have Rust installed. If you don't have it yet:

**Windows:**
```powershell
# Download and run rustup-init.exe from https://rustup.rs/
# Or use winget
winget install Rustlang.Rustup
```

**macOS/Linux:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Verify installation:
```bash
rustc --version
cargo --version
```

Important build dependencies for native/model backends:
- CMake: required to build some native C/C++ crates (for example the llama.cpp bindings used by the local LLM engine). Download: https://cmake.org/download/
- LLVM: required by some model/backends and native toolchains used by `llama_cpp_2` and related crates. Download: https://github.com/llvm/llvm-project/releases

If you see errors building the Rust program (linker or C bindings failures), make sure CMake and LLVM are installed and available on your PATH before building.

### Building for Development

Navigate to the engine directory and build:

```bash
cd program/guftron_engine
cargo build
```

The executable will be in `target/debug/gurftron_engine` (or `gurftron_engine.exe` on Windows).

### Building for Production

For optimized release builds:

```bash
cargo build --release
```

The optimized binary will be in `target/release/gurftron_engine` with significantly better performance and smaller size.

### Building with Specific Features

The project uses several key dependencies:

- **tokio**: Async runtime for non-blocking I/O
- **rusqlite**: SQLite database for scan caching
- **reqwest**: HTTP client for downloading ClamAV
- **serde/serde_json**: JSON serialization for native messaging
- **sha2**: File hashing for integrity checks
- **sysinfo**: Process monitoring for daemon management
- **indicatif**: Progress bars for downloads

All dependencies are automatically handled by Cargo.

## Running the Engine

### First-Time Setup

When you run the engine for the first time, it will:

1. Check for ClamAV installation
2. Download and install ClamAV if not found (Windows only)
3. Configure ClamAV with optimal settings
4. Start the ClamAV daemon
5. Update virus definitions
6. Register native messaging hosts with installed browsers

**Run the setup:**
```bash
# Development build
cargo run

# Or use the release build
cargo run --release
```

### Manual Registration

To register the native messaging host manually:

```bash
# This happens automatically on first run, but you can force it
./target/release/gurftron_engine
```

The engine will create manifest files in:
- **Windows**: Registry entries under `HKEY_CURRENT_USER\Software\[Browser]\NativeMessagingHosts`
- **macOS**: `~/Library/Application Support/[Browser]/NativeMessagingHosts/`
- **Linux**: `~/.config/[browser]/NativeMessagingHosts/` or `~/.mozilla/native-messaging-hosts/`

### Running as a Service

The engine is designed to be invoked by browser extensions through native messaging, not as a long-running service. Each browser instance will start its own engine process when needed.

## Usage

### Message Protocol

The engine accepts JSON messages via stdin and returns JSON responses via stdout.

**Scan a file:**
```json
{
  "action": "scan",
  "path": "/path/to/file.exe"
}
```

**Response:**
```json
{
  "result": "scan_initiated",
  "details": "Scan started - use scan_id to check status",
  "file_id": "sha256_hash_of_file",
  "scan_id": "unique-uuid",
  "scan_status": "pending"
}
```

**Check scan status:**
```json
{
  "action": "check_scan",
  "scan_id": "unique-uuid"
}
```

**Response (when complete):**
```json
{
  "result": "clean",
  "details": "File scanned successfully - no threats detected",
  "threat_level": "SAFE",
  "confidence": 0.95,
  "file_id": "sha256_hash",
  "scan_id": "unique-uuid",
  "scan_status": "completed"
}
```

**Get file hash:**
```json
{
  "action": "get_file_hash",
  "path": "/path/to/file"
}
```

**Ping check:**
```json
{
  "action": "ping"
}
```

### Supported Actions

- `scan` - Initiate file scan (async)
- `check_scan` - Check scan result by ID
- `get_file_hash` - Calculate SHA-256 hash
- `ping` - Health check

## ClamAV Installation

### Automatic Installation (Windows)

The engine automatically downloads and installs ClamAV on Windows if not found. It:
- Downloads the latest ClamAV build from Cisco
- Extracts to `C:\Program Files\ClamAV`
- Configures `freshclam.conf` and `clamd.conf`
- Adds ClamAV to PATH
- Updates virus definitions

### Manual Installation

**Windows:**
```powershell
# Download from: https://www.clamav.net/downloads
# Or use Chocolatey
choco install clamav
```

**macOS:**
```bash
brew install clamav
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install clamav clamav-daemon
sudo systemctl start clamav-daemon
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install clamav clamav-update clamd
sudo systemctl start clamd
```

### Configuration

The engine expects ClamAV to listen on TCP port 3310. Default configuration files are automatically generated with these settings:

**freshclam.conf:**
```
DatabaseMirror database.clamav.net
```

**clamd.conf:**
```
TCPSocket 3310
TCPAddr 127.0.0.1
```

## Database Schema

The engine uses SQLite to store scan results:

```sql
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_hash TEXT,
    status TEXT NOT NULL,
    result TEXT,
    details TEXT,
    threat_level TEXT,
    confidence REAL,
    created_at INTEGER NOT NULL,
    completed_at INTEGER
);
```

Database location:
- **Windows**: `%LOCALAPPDATA%\gurftron_scans.db`
- **macOS/Linux**: `~/.local/share/gurftron_scans.db` or `/tmp/gurftron_scans.db`

## Testing

### Run Tests

```bash
cargo test
```

### Manual Testing

Test the native messaging protocol manually:

```bash
# Build first
cargo build --release

# Send a test message (Windows PowerShell)
echo '{"action":"ping"}' | .\target\release\gurftron_engine.exe

# Send a test message (Unix)
echo '{"action":"ping"}' | ./target/release/gurftron_engine
```

### Testing with Browser Extension

1. Build the engine
2. Run it once to register native messaging
3. Load the browser extension
4. Trigger a file scan from the extension
5. Check browser console for communication logs

## Troubleshooting

### ClamAV Daemon Not Starting

**Check if ClamAV is installed:**
```bash
# Windows
where clamd

# macOS/Linux
which clamd
```

**Manually start daemon:**
```bash
# Windows
clamd.exe

# macOS/Linux
clamd
```

**Check logs:**
- Windows: `C:\Program Files\ClamAV\logs\`
- macOS: `/usr/local/var/log/clamav/`
- Linux: `/var/log/clamav/`

### Native Messaging Not Working

**Verify manifest registration:**
- Check registry (Windows) or manifest files (macOS/Linux)
- Ensure executable path in manifest is correct
- Restart browser after registration

**Check extension ID:**
Ensure the extension ID in `main.rs` matches your extension:
```rust
const CHROME_EXTENSION_ID: &str = "fhifdclndenfegminpkafeghdhdhadni";
const FIREFOX_EXTENSION_ID: &str = "gurftron@security.com";
```

### Scan Failures

**Port 3310 already in use:**
```bash
# Windows
netstat -ano | findstr :3310

# macOS/Linux
lsof -i :3310
```

**Virus definitions outdated:**
```bash
freshclam
```

**Timeout errors:**
Increase timeout in code if scanning large files (default: 60s)

## Performance Tuning

### Optimize Scan Speed

- Use release builds (`--release` flag)
- Increase chunk size for large files
- Ensure ClamAV has sufficient memory
- Use SSD for database storage

### Memory Usage

The engine uses streaming to minimize memory footprint:
- 64KB chunks for file transfers
- Async operations prevent blocking
- SQLite connection pooling

### Concurrent Scans

Multiple scans can run simultaneously. Each scan gets a unique ID and is tracked independently in the database.

## Security Considerations

- Native messaging only accepts connections from authorized extension IDs
- File paths are validated before scanning
- Maximum message size enforced (1MB)
- Timeouts prevent resource exhaustion
- SHA-256 hashing ensures file integrity
- No file modifications - read-only operations

## Platform-Specific Notes

### Windows
- Registry-based manifest registration
- Automatic ClamAV installation support
- PATH manipulation for daemon access

### macOS
- File-based manifest registration
- Requires Homebrew for ClamAV
- May need admin password for installation

### Linux
- File-based manifest registration
- Distribution-specific package managers
- May need systemd configuration for daemon

## Development

### Project Structure

```
src/
  main.rs              # Entry point, native messaging, daemon management
Cargo.toml             # Dependencies and project metadata
Cargo.lock             # Locked dependency versions
target/
  debug/               # Development builds
  release/             # Optimized builds
```

### Code Organization

- **Error Handling**: Custom `GurftronError` type for unified errors
- **Database Layer**: `ScanDatabase` struct with async methods
- **Native Messaging**: Stdin/stdout protocol handlers
- **ClamAV Integration**: TCP socket communication
- **Platform Support**: Conditional compilation for OS-specific code

### Contributing Guidelines

When modifying the code:
1. Maintain async/await patterns
2. Use proper error handling with `?` operator
3. Add logging with `tracing` macros
4. Test on multiple platforms
5. Keep native messaging protocol backward-compatible

## Building for Distribution

### Create Standalone Binary

```bash
# Build with full optimizations
cargo build --release --target x86_64-pc-windows-msvc

# Strip debug symbols (Unix)
strip target/release/gurftron_engine
```

### Cross-Compilation

For building on one platform for another:

```bash
# Install target
rustup target add x86_64-unknown-linux-gnu

# Build for target
cargo build --release --target x86_64-unknown-linux-gnu
```

## License

This project is part of the Gurftron security suite. Check the main repository for license information.

## Support

For issues or questions:
- Check ClamAV documentation at [clamav.net](https://www.clamav.net/)
- Review Rust async programming guides
- Examine native messaging protocol specs for your browser
- Check the logs and error messages for specific issues

---

**Note**: This engine requires ClamAV to be installed and running. It cannot scan files without a working ClamAV daemon. The first run will attempt automatic setup, but manual installation may be required on some systems.
