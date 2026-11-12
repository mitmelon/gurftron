# Models

Put model files here, then list them in `../models.toml`.

```
models/
  Qwen3-0.6B-Q4_K_M.gguf
  bge-small-en-v1.5/        model.onnx  tokenizer.json  config.json
  protectai-guard/          model.onnx  tokenizer.json  config.json
  memory-classifier/        model.onnx  tokenizer.json
```

Where to get them:

- Qwen3 0.6B GGUF: the `Qwen/Qwen3-0.6B-GGUF` repository on Hugging Face (`Qwen3-0.6B-Q4_K_M.gguf`).
- BGE small: the `Xenova/bge-small-en-v1.5` ONNX port.
- Guard: `ProtectAI/deberta-v3-base-prompt-injection-v2` (export or download its `model.onnx`).
- Memory classifier: your own fine-tuned ModernBERT, exported to ONNX.

Model files are git-ignored.
