//! Tokenizer loading for ONNX models (GGUF models tokenize inside llama.cpp).

use std::path::Path;

use anyhow::{anyhow, Result};
use tokenizers::{PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

/// Load `tokenizer.json`, truncating at `max_len` tokens and padding each batch to its longest item.
pub fn load(path: &Path, max_len: usize) -> Result<Tokenizer> {
    let mut tokenizer = Tokenizer::from_file(path)
        .map_err(|e| anyhow!("could not read tokenizer {}: {e}", path.display()))?;

    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: max_len,
            ..Default::default()
        }))
        .map_err(|e| anyhow!("invalid truncation settings: {e}"))?;

    let mut padding = match tokenizer.get_padding() {
        Some(existing) => existing.clone(),
        None => {
            let (pad_token, pad_id) = ["[PAD]", "<pad>", "<|endoftext|>"]
                .iter()
                .find_map(|t| tokenizer.token_to_id(t).map(|id| ((*t).to_string(), id)))
                .unwrap_or_else(|| ("[PAD]".to_string(), 0));
            PaddingParams {
                pad_id,
                pad_token,
                ..Default::default()
            }
        }
    };
    // Never pad to a fixed 512 just because the file says so: it makes short inputs slow.
    padding.strategy = PaddingStrategy::BatchLongest;
    tokenizer.with_padding(Some(padding));

    Ok(tokenizer)
}
