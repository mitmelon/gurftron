# Manomite Loader

One Rust binary that loads local models and serves them over a single HTTP API: GGUF models for chat, ONNX models for embeddings and classification (including a prompt-injection guard). A small Node.js (Fastify) server adds a dashboard, a memory pipeline and a client for your own Node apps. No Ollama, no Python at runtime.

Built with [Arc Studio](https://studio.arc.io)

## What is in here

- `src/`, `Cargo.toml`, `models.toml`, `server.toml`: the Rust loader. Design in `spec.MD`.
- `gateway/`: the Fastify server, the dashboard (plain HTML, CSS and JS) and `loader-client.js`.
- `examples/full-flow.js`: guard, write, classify, embed using only `fetch` and `require`.
- `models/`: where your model files go (git-ignored). See `models/README.md`.

## Tech stack

Rust (axum, tokio, llama-cpp-2, ort, tokenizers) and Node.js 20+ (Fastify 5).

## Development

### Prerequisites

- Rust stable and `cargo`
- Linux: `build-essential`, `cmake`, `libclang-dev`. Windows: Visual Studio Build Tools and CMake.
- Node.js 20 or newer

### Run the loader

1. Put model files under `models/` and list them in `models.toml` (add a block, restart, no code change).
2. `cargo run --release` starts the API on `http://127.0.0.1:3000`. Nothing is loaded until the first request.

Build only one engine with `cargo build --release --no-default-features --features onnx` (or `gguf`).

### Run the dashboard server

```
cd gateway
npm install      # or: bun install
npm start        # http://127.0.0.1:8080
```

### Test

- Rust: `cargo test`
- Gateway: `cd gateway && npm test` (uses a fake loader, no models needed)

### Environment variables

All optional.

- `MANOMITE_HOST`, `MANOMITE_PORT`: override the loader's `server.host` and `server.port`.
- `RUST_LOG`: override the loader's log level.
- `LOADER_URL`: where the gateway finds the loader (default `http://127.0.0.1:3000`).
- `PORT`, `HOST`: gateway listen address (default `8080`, `127.0.0.1`).

## API

`GET /health`, `GET /v1/models`, `POST /v1/chat/completions` (JSON or SSE, `format: "json"` forces valid JSON), `POST /v1/embeddings`, `POST /v1/guard`, `POST /v1/classify`. Every error is `{ "error": { "code", "message", "model" } }`.

The loader binds to localhost only and has no authentication in v0.1.
