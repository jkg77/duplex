//! Duplicate File Analyzer
//!
//! A high-performance tool for identifying duplicate files across large directory structures.
//! This library provides the core functionality for file discovery, duplicate detection,
//! and result reporting.

use serde::{Deserialize, Serialize};

pub mod analysis;
pub mod concurrent;
pub mod discovery;
pub mod duplicate;
pub mod hash;
pub mod memory;
pub mod models;
pub mod progress;
pub mod report;
pub mod resume;
pub mod web;

pub use analysis::AnalysisController;
pub use models::*;

/// Result type used throughout the application
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Number of threads to use for parallel processing
    pub thread_count: usize,
    /// Hash algorithm to use
    pub hash_algorithm: HashAlgorithm,
    /// Maximum memory usage in bytes
    pub max_memory: usize,
    /// Batch size for processing files
    pub batch_size: usize,
    /// Maximum concurrent hash computations
    pub max_concurrent_hashes: usize,
}

impl Default for Config {
    fn default() -> Self {
        let cpu_count = num_cpus::get();
        Self {
            thread_count: cpu_count,
            hash_algorithm: HashAlgorithm::Sha256,
            max_memory: 1024 * 1024 * 1024, // 1GB
            batch_size: 1000,
            max_concurrent_hashes: cpu_count * 2, // Allow more concurrent I/O operations
        }
    }
}

/// Hash algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Md5,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Md5 => write!(f, "md5"),
        }
    }
}
