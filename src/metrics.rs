//! In-memory counters, exposed through `/health`.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ModelMetrics {
    pub requests: u64,
    pub errors: u64,
    pub avg_latency_ms: f64,
    pub last_load_ms: Option<u64>,
}

#[derive(Default)]
pub struct Metrics {
    per_model: Mutex<HashMap<String, ModelMetrics>>,
    evictions: AtomicU64,
}

impl Metrics {
    pub fn record_request(&self, model: &str, duration_ms: u64, ok: bool) {
        let mut map = self.per_model.lock().unwrap_or_else(|e| e.into_inner());
        let m = map.entry(model.to_string()).or_default();
        m.avg_latency_ms =
            (m.avg_latency_ms * m.requests as f64 + duration_ms as f64) / (m.requests + 1) as f64;
        m.requests += 1;
        if !ok {
            m.errors += 1;
        }
    }

    pub fn record_load(&self, model: &str, load_ms: u64) {
        let mut map = self.per_model.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(model.to_string()).or_default().last_load_ms = Some(load_ms);
    }

    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> HashMap<String, ModelMetrics> {
        self.per_model.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
