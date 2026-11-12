//! ONNX Runtime engine for embedding and classifier models (`ort` + `tokenizers`).

use std::{fs, path::Path};

use anyhow::{anyhow, bail, Result};
use ort::{
    session::{builder::GraphOptimizationLevel, Session},
    value::Tensor,
};
use tokenizers::Tokenizer;

use super::{Classification, ClassifierEngine, EmbeddingEngine, Engine};
use crate::config::{ModelConfig, ModelKind};
use crate::errors::{ApiError, ErrorCode};
use crate::tokenizer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pooling {
    Mean,
    Cls,
}

pub struct OnnxEngine {
    name: String,
    kind: ModelKind,
    session: Session,
    tokenizer: Tokenizer,
    input_names: Vec<String>,
    output_name: String,
    dim: usize,
    labels: Vec<String>,
    normalize: bool,
    pooling: Pooling,
    mem_mb: u64,
}

fn infer_err<E: std::fmt::Display>(e: E) -> ApiError {
    ApiError::new(ErrorCode::InternalError, format!("inference failed: {e}"))
}

/// Read `id2label` from a Hugging Face `config.json` that sits next to the model.
fn labels_from_config(model_path: &Path) -> Option<Vec<String>> {
    let text = fs::read_to_string(model_path.parent()?.join("config.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let map = json.get("id2label")?.as_object()?;
    let mut pairs: Vec<(usize, String)> = map
        .iter()
        .filter_map(|(k, v)| Some((k.parse().ok()?, v.as_str()?.to_string())))
        .collect();
    pairs.sort_by_key(|(i, _)| *i);
    Some(pairs.into_iter().map(|(_, l)| l).collect())
}

impl OnnxEngine {
    pub fn load(cfg: &ModelConfig) -> Result<Self> {
        let model_path = cfg.resolved_path();
        let tok_path = cfg
            .resolved_tokenizer()
            .ok_or_else(|| anyhow!("no tokenizer configured"))?;
        let tokenizer = tokenizer::load(&tok_path, cfg.max_length.unwrap_or(512))?;

        let threads = cfg.n_threads.unwrap_or(2).max(1);
        let session = Session::builder()
            .and_then(|b| b.with_optimization_level(GraphOptimizationLevel::Level3))
            .and_then(|b| b.with_intra_threads(threads))
            .and_then(|b| b.commit_from_file(&model_path))
            .map_err(|e| anyhow!("could not load ONNX model: {e}"))?;

        let input_names: Vec<String> = session.inputs.iter().map(|i| i.name.clone()).collect();
        for name in &input_names {
            if !matches!(name.as_str(), "input_ids" | "attention_mask" | "token_type_ids") {
                bail!("model needs an input '{name}' this loader cannot provide");
            }
        }
        let output_names: Vec<String> = session.outputs.iter().map(|o| o.name.clone()).collect();
        let output_name = output_names
            .iter()
            .find(|n| n.as_str() == "last_hidden_state" || n.as_str() == "logits")
            .or_else(|| output_names.first())
            .cloned()
            .ok_or_else(|| anyhow!("model has no outputs"))?;

        let labels = match cfg.kind {
            ModelKind::Classifier => cfg
                .labels
                .clone()
                .or_else(|| labels_from_config(&model_path))
                .ok_or_else(|| anyhow!("classifier needs `labels` in models.toml or id2label in config.json"))?,
            _ => Vec::new(),
        };
        let pooling = match cfg.pooling.as_deref().unwrap_or("mean") {
            "mean" => Pooling::Mean,
            "cls" => Pooling::Cls,
            other => bail!("unknown pooling '{other}' (use mean or cls)"),
        };

        let size_mb = fs::metadata(&model_path).map(|m| m.len() / (1024 * 1024)).unwrap_or(0);
        Ok(Self {
            name: cfg.name.clone(),
            kind: cfg.kind,
            session,
            tokenizer,
            input_names,
            output_name,
            dim: cfg.dim.unwrap_or(0),
            labels,
            normalize: cfg.normalize.unwrap_or(true),
            pooling,
            mem_mb: size_mb * 13 / 10 + 20,
        })
    }

    /// Tokenize a batch, run the graph once, and return (flat output, output shape, attention masks, seq_len).
    fn run(&mut self, texts: &[String]) -> Result<(Vec<f32>, Vec<i64>, Vec<Vec<u32>>), ApiError> {
        let encodings = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| ApiError::invalid(format!("could not tokenize input: {e}")))?;
        let batch = encodings.len();
        let seq = encodings.first().map_or(0, |e| e.get_ids().len());
        if seq == 0 {
            return Err(ApiError::invalid("input produced no tokens"));
        }

        let mut ids = Vec::with_capacity(batch * seq);
        let mut mask = Vec::with_capacity(batch * seq);
        let mut types = Vec::with_capacity(batch * seq);
        let mut masks = Vec::with_capacity(batch);
        for e in &encodings {
            ids.extend(e.get_ids().iter().map(|&x| i64::from(x)));
            mask.extend(e.get_attention_mask().iter().map(|&x| i64::from(x)));
            types.extend(e.get_type_ids().iter().map(|&x| i64::from(x)));
            masks.push(e.get_attention_mask().to_vec());
        }

        let shape = [batch, seq];
        let mut inputs: Vec<(String, Tensor<i64>)> = Vec::new();
        for name in &self.input_names {
            let data = match name.as_str() {
                "input_ids" => ids.clone(),
                "attention_mask" => mask.clone(),
                _ => types.clone(),
            };
            inputs.push((name.clone(), Tensor::from_array((shape, data)).map_err(infer_err)?));
        }

        let outputs = self.session.run(inputs).map_err(infer_err)?;
        let (out_shape, data) = outputs[self.output_name.as_str()]
            .try_extract_tensor::<f32>()
            .map_err(infer_err)?;
        Ok((data.to_vec(), out_shape.to_vec(), masks))
    }
}

impl Engine for OnnxEngine {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> ModelKind {
        self.kind
    }
    fn memory_mb(&self) -> u64 {
        self.mem_mb
    }
}

fn l2_normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-12 {
        v.iter_mut().for_each(|x| *x /= norm);
    }
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.into_iter().map(|x| x / sum).collect()
}

impl EmbeddingEngine for OnnxEngine {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed_batch(&mut self, texts: &[String]) -> Result<Vec<Vec<f32>>, ApiError> {
        let (data, shape, masks) = self.run(texts)?;
        let batch = texts.len();

        let mut out: Vec<Vec<f32>> = match shape.as_slice() {
            // [batch, seq, hidden]: pool over tokens.
            [b, s, h] if *b as usize == batch => {
                let (s, h) = (*s as usize, *h as usize);
                (0..batch)
                    .map(|i| {
                        let rows = &data[i * s * h..(i + 1) * s * h];
                        match self.pooling {
                            Pooling::Cls => rows[..h].to_vec(),
                            Pooling::Mean => {
                                let mut acc = vec![0f32; h];
                                let mut count = 0f32;
                                for (t, row) in rows.chunks(h).enumerate() {
                                    if masks[i].get(t).copied().unwrap_or(0) == 1 {
                                        acc.iter_mut().zip(row).for_each(|(a, x)| *a += x);
                                        count += 1.0;
                                    }
                                }
                                acc.iter_mut().for_each(|a| *a /= count.max(1.0));
                                acc
                            }
                        }
                    })
                    .collect()
            }
            // [batch, hidden]: the graph already pooled.
            [b, h] if *b as usize == batch => {
                data.chunks(*h as usize).map(<[f32]>::to_vec).collect()
            }
            other => {
                return Err(infer_err(format!("unexpected output shape {other:?} for an embedding model")))
            }
        };

        let got = out.first().map_or(0, Vec::len);
        if self.dim != 0 && got != self.dim {
            return Err(infer_err(format!(
                "model produced {got}-dim vectors but models.toml says dim = {}",
                self.dim
            )));
        }
        self.dim = got;
        if self.normalize {
            out.iter_mut().for_each(|v| l2_normalize(v));
        }
        Ok(out)
    }
}

impl ClassifierEngine for OnnxEngine {
    fn labels(&self) -> &[String] {
        &self.labels
    }

    fn classify(&mut self, text: &str) -> Result<Classification, ApiError> {
        let (data, shape, _) = self.run(&[text.to_string()])?;
        let n = match shape.as_slice() {
            [1, n] => *n as usize,
            other => return Err(infer_err(format!("unexpected output shape {other:?} for a classifier"))),
        };
        if n != self.labels.len() {
            return Err(infer_err(format!(
                "model has {n} outputs but {} labels are configured",
                self.labels.len()
            )));
        }
        let probs = softmax(&data[..n]);
        let (best, score) = probs
            .iter()
            .copied()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .ok_or_else(|| infer_err("empty logits"))?;
        Ok(Classification {
            label: self.labels[best].clone(),
            score,
            all_scores: self.labels.iter().cloned().zip(probs).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_sums_to_one() {
        let p = softmax(&[2.0, 1.0, -1.0]);
        assert!((p.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!(p[0] > p[1] && p[1] > p[2]);
    }

    #[test]
    fn normalize_gives_unit_length() {
        let mut v = vec![3.0, 4.0];
        l2_normalize(&mut v);
        assert!(((v[0] * v[0] + v[1] * v[1]) - 1.0).abs() < 1e-6);
    }
}
