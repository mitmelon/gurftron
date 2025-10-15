This file is a short, actionable guide for AI coding agents (Copilot-style) working in the Gurftron repository.

Keep instructions concrete and limited to patterns discoverable in the codebase. When making changes, prefer small, well-tested edits and preserve existing behavior unless the task explicitly requires behavior changes.

Key facts (big picture)
- Project: a Chrome extension + backend tooling for AI-assisted phishing protection and Starknet integration.
- Major components:
  - `src/` — Extension frontend: `content.js`, `gurftron.js`, `background.js` (service worker), UI pages (`*.html`, `*.js`).
  - `gurftron-server/` — minimal Node server used by development `npm start`.
  - `contracts/` — Cairo smart-contracts (see `contracts/README.md`).
  - `program/guftron_engine/` — Rust engine (native scanning, optional native messaging host).

Where LLMs live
- All LLM orchestration is implemented in `src/background.js`. The background service builds prompts with `buildAnalysisPrompt()` and calls Gemini via `performGeminiAPIAnalysis()` -> `performGeminiAPIAnalysis` -> `performGeminiAPIAnalysis`/`performGeminiAPIAnalysis` (see the Gemini wrappers: `performGeminiAPIAnalysis`, `performGeminiAPIAnalysis` calls `performGeminiAPIAnalysis` and `executeSingleGeminiRequest`).
- Content script (`src/content.js`) never calls external LLMs directly — it forwards analysis requests to background via `chrome.runtime.sendMessage({ action: 'llm_analyze' })` or `action: 'analyzeThreat'`.

Message contracts (extension IPC)
- Content -> Background
  - `{ action: 'llm_analyze', text, type }` — background will run LLM and return {threat, confidence, details}. Used by `content.js` `analyzeWithLLM`.
  - `{ action: 'analyzeThreat', data, prompt }` — background runs analysis and persists high-confidence results.
  - `{ action: 'api_call', api, params }` — proxy for external APIs (safebrowsing, phishtank, abuseipdb, etc.).
  - `{ action: 'scan', type, data }` — background helpers (cpu_monitor, resource_headers, image_stego_check, link_snippet).
  - `{ type: 'GURFTRON_GET_INJECT_SIGNATURE', injectedId, secureId }` — returns {signature, ts} for injected script trust.

Important files to reference when editing
- `src/background.js` — LLM prompt templates, Gemini integration, API proxying, rate limiting, webRequest hooks.
- `src/content.js` — page scanning orchestration, mutation observer, how evidence is built and sent to the background worker. Many helper methods call `chrome.runtime.sendMessage` with well-defined actions.
- `src/gurftron.js` — injected page helper (start/stop monitoring) — used by the content script; check `window.postMessage` interactions.
- `src/dexieStorage.js` — Dexie wrapper used by background for persistence (storage adapter); use when changing storage shape.
- `gurftron-server/server.js` — backend server used by `npm start`.

Project-specific patterns and conventions
- Prompt-injection safety: background implements `detectPromptInjection(text)` and will suppress calls if suspicious. When generating or refactoring prompt text, follow existing templates in `buildAnalysisPrompt()` to maintain the same JSON-output expectations.
- LLM responses are expected to be strict JSON. Background strips code fences and tolerates non-JSON by searching for threat keywords. Preserve this behavior unless updating the parsing logic in `executeSingleGeminiRequest()`.
- Rate limiting: background enforces per-tab LLM rate limiting (MAX_LLM_CALLS_PER_MIN). If adding new LLM callers, ensure they respect the same rate-limiter map `_gurftron_rateLimiter`.
- Signature verification: injected script uses `GURFTRON_GET_INJECT_SIGNATURE` / `verifyInjectedSignature()` for trust. If changing injection or signing, update both content and background functions.
- Storage: high-level storage calls go through `DexieStorageAdapter` (see `src/dexieStorage.js`). When changing data shapes, update migration logic here and any consumers.

Debugging notes and common fixes (from current run traces)
- Local dev server: `npm run start` starts the Node server at `gurftron-server/server.js`. For extension development you typically run `npm run dev` (webpack watch) then load the unpacked `src/` as an extension in Chrome (manifest is at repo root `manifest.json`).
- Missing Gemini key: Many LLM failures are due to `geminiApiKey` not set in `chrome.storage.sync` — background returns error `NO_API_KEY`. To test LLM flows locally, set `geminiApiKey` using the extension storage or adapt code to read from `.env` only in dev server tests.
- CORS / external resource 404s: content-side fetches for remote pages can 404 (e.g., injected assets) — those are expected when testing against ngrok or staging hosts. Focus on extension messaging and background LLM logs to debug LLM behavior.
- Chrome runtime errors like `A listener indicated an asynchronous response by returning true, but the message channel closed` indicate message handler functions didn't call `sendResponse` or returned incorrectly. Background and content message listeners generally return `true` when they call sendResponse asynchronously — keep that convention.

Editing guidance and example tasks
- Small bugfix (example): If `content.js` logs `Could not establish connection. Receiving end does not exist.`, check that background `chrome.runtime.onMessage` is present and returns `true` for async handlers (we do this already). If you add new asynchronous onMessage paths, ensure you `return true;` in the listener.
- Add tests or instrumentation: Add small unit tests or add structured logs in `background.js` `performGeminiAPIAnalysis()` or `executeSingleGeminiRequest()` to capture Gemini request/response shapes. Prefer non-blocking logs and avoid leaking API keys.
- If changing LLM prompt shapes, update `buildAnalysisPrompt()` templates and ensure `detectPromptInjection()` doesn't incorrectly flag benign prompts. When in doubt, keep behavior conservative — false negatives are preferable to false positives in threat detection.

Examples taken from codebase
- How content triggers LLM analysis: `src/content.js` -> analyzeWithLLM -> sendMessageSafe({ action: 'llm_analyze', text: payloadText, type: category })
- How background wraps Gemini: `src/background.js` -> buildAnalysisPrompt() -> performGeminiAPIAnalysis(prompt) -> executeSingleGeminiRequest(prompt, apiKey)

Quality gates
- Run `npm run dev` (webpack) to build extension UI assets; use `npm start` to run the local server.
- After edits, verify no syntax errors in modified files and verify background message handlers still return `true` for async flows. Unit tests are not present; rely on runtime smoke-tests: load extension unpacked and exercise `testLLM()` from content script console: `window.gurftronDetector.testLLM()`.

When unsure
- If a change touches cross-file behaviors (injection signing, storage shape, LLM prompt scaffolding), make the minimal change and add a short note in the PR describing the risk and manual verification steps (how to trigger `testLLM()` and where to look in console logs: `content.js` logs prefixed with `[Gurftron ... INFO]` and background logs `🤖 Background:`).

If you edit this file, ask the repository owner for examples of expected runtime environment (Gemini API key location and native host name) before making changes that rely on them.

-- End of Copilot instructions --
