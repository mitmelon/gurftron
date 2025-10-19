# 🛡️ Gurftron Engine — Native Antivirus & Local LLM

Gurftron Engine is a high-performance native security host written in Rust that provides real-time malware scanning and AI-powered threat analysis directly on your machine.

## ✨ Features

- **🦠 ClamAV-Based Scanning**: Fast asynchronous file scanning with virus signature database
- **🤖 Local LLM Intelligence**: Privacy-focused AI reasoning using llama.cpp (no data leaves your machine)
- **🔌 Browser Integration**: Native messaging bridge for Chrome, Brave, Edge, and Firefox extensions
- **💾 Smart Caching**: SQLite-backed scan history prevents duplicate scans
- **⚡ Async Operations**: Non-blocking file scanning with progress tracking
- **🔐 SHA-256 Hashing**: Fast file fingerprinting for integrity verification

---

## 📋 Requirements

### 🔧 Build Dependencies (Critical)

**⚠️ Rust program not compiling?** Make sure you have **CMake** and **LLVM** installed on your computer.

1. **Rust toolchain** (rustc + cargo)  
   📥 Install from: https://rustup.rs/

2. **CMake** (required for llama.cpp native bindings)  
   📥 Download: https://cmake.org/download/  
   ✅ Ensure `cmake` is available in your PATH

3. **LLVM / Clang** (required for native C/C++ compilation)  
   📥 Download: https://github.com/llvm/llvm-project/releases  
   ✅ Ensure `clang` is available in your PATH

> **💡 Tip**: If `cargo build` fails with linker errors or missing symbols, verify that both CMake and LLVM are properly installed and accessible from your terminal.

### 🏃 Runtime Dependencies (Auto-Installed)

- **ClamAV** (`clamd` + `freshclam`) — The engine will attempt to auto-install ClamAV on first run:
  - **Windows**: Downloads and installs ClamAV automatically
  - **macOS**: Installs via Homebrew (`brew install clamav`)
  - **Linux**: Uses system package manager (apt/dnf/yum)

---

## 🚀 Building the Engine

### Development Build

```powershell
cd program\gurftron_engine
cargo build
```

**Output**: `target/debug/gurftron_engine.exe` (Windows) or `target/debug/gurftron_engine` (Unix)

### Release Build (Optimized)

```powershell
cargo build --release
```

**Output**: `target/release/gurftron_engine.exe` (Windows) or `target/release/gurftron_engine` (Unix)

---

## 🎯 Running the Engine

### First Run Setup

On first execution, the engine will:
1. ✅ Install ClamAV (if not present)
2. ✅ Update virus signature database (`freshclam`)
3. ✅ Register native messaging manifests for browser extensions
4. ✅ Start ClamAV daemon (`clamd`)
5. ✅ Initialize SQLite scan database
6. 🤖 Download and initialize local LLM model (based on available RAM)

```powershell
# Run in development mode
cargo run

# Run optimized release build
cargo run --release
```

### Subsequent Runs

The engine starts immediately and listens for native messaging commands from browser extensions.

---

## 🤖 Local LLM Integration

### What It Does

The engine includes an **optional local AI assistant** powered by llama.cpp that can:
- 🧠 Analyze threat evidence and generate security summaries
- 💬 Answer security-related questions
- 📊 Provide natural language explanations of scan results
- 🔒 **100% private** — no data sent to external servers

### Available Models

The engine automatically selects the best model based on your system RAM:

| Model | RAM Required | Size | Quantization | Description |
|-------|-------------|------|--------------|-------------|
| **TinyLlama-1.1B** | 2 GB | 669 MB | Q4_K_M | ⚡ Fast lightweight model |
| **Phi-2-2.7B** | 4 GB | 1.5 GB | Q4_K_M | ⚖️ Balanced performance |
| **Mistral-7B-Instruct** | 8 GB | 4.3 GB | Q4_K_M | 🎯 High quality responses |
| **Llama-3-8B-Instruct** | 16 GB | 4.9 GB | Q4_K_M | 🏆 State-of-the-art accuracy |

### Model Storage

- **Location**: Platform data directory + `gurftron_models`
  - Windows: `%LOCALAPPDATA%\gurftron_models`
  - macOS: `~/Library/Application Support/gurftron_models`
  - Linux: `~/.local/share/gurftron_models`

- Models are downloaded **once** from Hugging Face and cached locally
- Downloads show real-time progress bars with speed and ETA

### LLM Initialization Behavior

- LLM initialization happens **asynchronously** during engine startup
- If initialization fails (low RAM, missing dependencies), the engine continues with scanning-only mode
- Chat completion features gracefully disable if LLM unavailable

---

## 📡 Native Messaging Protocol

The engine communicates with browser extensions using JSON messages over length-prefixed stdin/stdout.

### Available Actions

#### 1. 🦠 `scan` — Start Asynchronous File Scan

**Request:**
```json
{
  "action": "scan",
  "path": "C:\\Users\\Downloads\\suspicious.exe"
}
```

**Response:**
```json
{
  "result": "scan_initiated",
  "details": "Scan started - use scan_id to check status",
  "file_id": "a1b2c3d4...",
  "scan_id": "uuid-1234-5678",
  "scan_status": "pending"
}
```

#### 2. 🔍 `check_scan` — Query Scan Result

**Request:**
```json
{
  "action": "check_scan",
  "scan_id": "uuid-1234-5678"
}
```

**Response (Clean File):**
```json
{
  "result": "clean",
  "details": "File scanned successfully - no threats detected",
  "threat_level": "SAFE",
  "confidence": 0.95,
  "scan_status": "completed"
}
```

**Response (Threat Detected):**
```json
{
  "result": "infected",
  "details": "Win.Trojan.Generic FOUND",
  "threat_level": "HIGH",
  "confidence": 0.98,
  "scan_status": "completed"
}
```

#### 3. 🔐 `get_file_hash` — Calculate SHA-256

**Request:**
```json
{
  "action": "get_file_hash",
  "path": "C:\\Users\\Documents\\file.pdf"
}
```

**Response:**
```json
{
  "result": "hash_calculated",
  "details": "SHA-256 hash calculated successfully",
  "file_id": "a1b2c3d4e5f6..."
}
```

#### 4. 💓 `ping` — Health Check

**Request:**
```json
{
  "action": "ping"
}
```

**Response:**
```json
{
  "result": "success",
  "details": "Gurftron Antivirus Engine is active and ready",
  "threat_level": "SAFE",
  "confidence": 1.0
}
```

#### 5. 🤖 `chat_completion` — LLM Inference

**Request:**
```json
{
  "action": "chat_completion",
  "messages": [
    {
      "role": "system",
      "content": "You are a cybersecurity assistant."
    },
    {
      "role": "user",
      "content": "Explain what a phishing attack is in simple terms."
    }
  ],
  "max_tokens": 256,
  "temperature": 0.7,
  "top_p": 0.9
}
```

**Response:**
```json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1729353600,
  "model": "Phi-2-2.7B",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "A phishing attack is when cybercriminals..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 45,
    "completion_tokens": 128,
    "total_tokens": 173
  }
}
```

**Parameters:**
- `messages`: Array of chat messages (system/user/assistant roles)
- `max_tokens`: Maximum tokens to generate (default: 512)
- `temperature`: Randomness (0.0-1.0, default: 0.7)
- `top_p`: Nucleus sampling threshold (default: 0.9)
- `stream`: Enable streaming (not yet implemented)

#### 6. ℹ️ `model_info` — Get LLM Model Details

**Request:**
```json
{
  "action": "model_info"
}
```

**Response:**
```json
{
  "result": "success",
  "model_info": {
    "name": "Phi-2-2.7B",
    "repo_id": "TheBloke/phi-2-GGUF",
    "filename": "phi-2.Q4_K_M.gguf",
    "min_ram_gb": 4,
    "size_mb": 1560,
    "description": "Balanced performance",
    "quantization": "Q4_K_M"
  }
}
```

---

## 💾 Scan Caching & Database

### How It Works

- All scan results are stored in SQLite database: `gurftron_scans.db`
- Files are fingerprinted using SHA-256 hashing
- **Smart caching**: If a file hasn't changed (same hash), previous scan result is returned instantly
- Scan history persists across engine restarts

### Database Schema

```sql
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_hash TEXT,
    status TEXT NOT NULL,          -- pending, scanning, completed
    result TEXT,                    -- clean, infected, error
    details TEXT,
    threat_level TEXT,              -- SAFE, LOW, MEDIUM, HIGH
    confidence REAL,
    created_at INTEGER NOT NULL,
    completed_at INTEGER
);
```

---

## 🔌 Browser Extension Integration

### Supported Browsers

- ✅ Google Chrome
- ✅ Microsoft Edge
- ✅ Brave Browser
- ✅ Mozilla Firefox

### Native Messaging Manifest

The engine automatically registers native messaging manifests in:

**Windows Registry:**
- `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts`
- `HKEY_CURRENT_USER\Software\Microsoft\Edge\NativeMessagingHosts`
- `HKEY_CURRENT_USER\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts`
- `HKEY_CURRENT_USER\Software\Mozilla\NativeMessagingHosts`

**Host Name:** `com.gurftron.server`

---

## 🐛 Troubleshooting

### Build Failures

**❌ Error: "linker error" or "undefined reference"**  
✅ **Solution**: Install CMake and LLVM, ensure they're in your PATH

**❌ Error: "failed to run custom build command for llama-cpp-sys-2"**  
✅ **Solution**: Install CMake (https://cmake.org/) and restart your terminal

**❌ Error: "cannot find -lclang" or "clang not found"**  
✅ **Solution**: Install LLVM (https://github.com/llvm/llvm-project/releases)

### Runtime Errors

**❌ ClamAV daemon not starting**  
✅ **Check**: Port 3310 is not already in use  
✅ **Fix**: Kill existing `clamd` process or change port in config

**❌ LLM initialization fails**  
✅ **Check**: System has enough RAM for selected model  
✅ **Note**: Engine continues with scanning-only mode

**❌ "Failed to connect to ClamAV daemon"**  
✅ **Fix**: Run `freshclam` to update virus database  
✅ **Fix**: Manually start clamd daemon

### Quick Diagnostic Commands

```powershell
# Check if ClamAV is installed
where clamd

# Check if CMake is installed
where cmake

# Check if Clang is installed
where clang

# Test engine health
echo '{"action":"ping"}' | .\target\release\gurftron_engine.exe
```

---

## 📦 Dependencies

### Core Dependencies
- `tokio` — Async runtime with full feature set
- `serde` & `serde_json` — JSON serialization
- `rusqlite` — SQLite database (bundled)
- `llama-cpp-2` — Local LLM inference
- `sha2` & `hex` — Cryptographic hashing
- `reqwest` — HTTP client for model downloads
- `indicatif` — Progress bars
- `chrono` — Timestamp handling
- `uuid` — Unique identifier generation

### Platform-Specific
- **Windows**: `winreg` — Registry access for native messaging
- `sysinfo` — System information and process monitoring
- `which` — Executable path resolution
- `dirs` — Platform-specific directory paths

---

## 🏗️ Architecture

```
Browser Extension
       ↓ (Native Messaging via stdin/stdout)
Gurftron Engine (Rust)
       ↓ (TCP Socket - Port 3310)
ClamAV Daemon (clamd)
       ↓
Virus Signature Database
```

### Communication Flow

1. Browser extension sends JSON message via native messaging
2. Engine parses request and initiates async scan
3. Engine connects to ClamAV daemon over TCP
4. File is streamed in 64KB chunks to ClamAV
5. Scan result is stored in SQLite database
6. Engine returns structured JSON response to browser

---

## 🧪 Testing

### Manual Testing

**Ping test:**
```powershell
echo '{"action":"ping"}' | .\target\release\gurftron_engine.exe
```

**Scan test:**
```powershell
echo '{"action":"scan","path":"C:\\Windows\\notepad.exe"}' | .\target\release\gurftron_engine.exe
```

> **Note**: Native messaging uses 4-byte little-endian length prefix. For proper testing, use the browser extension or create a helper script.

---

## 📄 License

Part of the Gurftron security suite — See main repository for license details.

---

## 🤝 Contributing

Contributions welcome! Focus areas:
- 🔍 Additional malware detection engines
- 🤖 LLM prompt optimization for security analysis
- 🚀 Performance improvements
- 📚 Documentation enhancements
- 🧪 Test coverage expansion

---

**Built with ❤️ using Rust 🦀**
