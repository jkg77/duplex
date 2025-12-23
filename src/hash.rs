//! Hash computation utilities for file content verification

use crate::{concurrent::FileMetadataExt, HashAlgorithm, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};

/// Cache entry for a computed hash
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HashCacheEntry {
    /// The computed hash value
    hash: String,
    /// File size when hash was computed
    file_size: u64,
    /// File modification time when hash was computed
    modified_time: SystemTime,
    /// Hash algorithm used
    algorithm: HashAlgorithm,
}

/// In-memory and persistent cache for file hashes
#[derive(Debug)]
pub struct HashCache {
    /// In-memory cache
    cache: HashMap<PathBuf, HashCacheEntry>,
    /// Path to persistent cache file
    cache_file: Option<PathBuf>,
    /// Maximum number of entries to keep in memory
    max_entries: usize,
}

impl HashCache {
    /// Create a new hash cache
    pub fn new(cache_file: Option<PathBuf>, max_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            cache_file,
            max_entries,
        }
    }

    /// Get a cached hash if it's still valid
    pub async fn get(&self, file_path: &Path, algorithm: HashAlgorithm) -> Option<String> {
        let entry = self.cache.get(file_path)?;
        
        // Check if algorithm matches
        if entry.algorithm != algorithm {
            return None;
        }
        
        // Check if file has been modified since hash was computed
        if let Ok(metadata) = tokio::fs::metadata(file_path).await {
            if metadata.len() == entry.file_size && 
               metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH) == entry.modified_time {
                return Some(entry.hash.clone());
            }
        }
        
        None
    }

    /// Store a hash in the cache
    pub async fn put(&mut self, file_path: PathBuf, hash: String, algorithm: HashAlgorithm) -> Result<()> {
        // Get file metadata for cache validation
        let metadata = tokio::fs::metadata(&file_path).await?;
        let file_size = metadata.len();
        let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        
        let entry = HashCacheEntry {
            hash,
            file_size,
            modified_time,
            algorithm,
        };
        
        self.cache.insert(file_path, entry);
        
        // Implement simple LRU eviction if cache is too large
        if self.cache.len() > self.max_entries {
            // Remove oldest entries (simple approach - in production might use proper LRU)
            let keys_to_remove: Vec<_> = self.cache.keys().take(self.cache.len() - self.max_entries).cloned().collect();
            for key in keys_to_remove {
                self.cache.remove(&key);
            }
        }
        
        Ok(())
    }

    /// Load cache from persistent storage
    pub async fn load(&mut self) -> Result<()> {
        if let Some(cache_file) = &self.cache_file {
            if cache_file.exists() {
                let contents = tokio::fs::read_to_string(cache_file).await?;
                let loaded_cache: HashMap<PathBuf, HashCacheEntry> = serde_json::from_str(&contents)?;
                self.cache = loaded_cache;
            }
        }
        Ok(())
    }

    /// Save cache to persistent storage
    pub async fn save(&self) -> Result<()> {
        if let Some(cache_file) = &self.cache_file {
            let contents = serde_json::to_string_pretty(&self.cache)?;
            let mut file = File::create(cache_file).await?;
            file.write_all(contents.as_bytes()).await?;
            file.flush().await?;
        }
        Ok(())
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.cache.len(), self.max_entries)
    }
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new(None, 10000) // Default to 10k entries, no persistence
    }
}
/// Computer for generating file content hashes
pub struct HashComputer {
    algorithm: HashAlgorithm,
    cache: HashCache,
}

impl HashComputer {
    /// Create a new hash computer
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { 
            algorithm,
            cache: HashCache::default(),
        }
    }

    /// Create a new hash computer with custom cache settings
    pub fn with_cache(algorithm: HashAlgorithm, cache_file: Option<PathBuf>, max_entries: usize) -> Self {
        Self {
            algorithm,
            cache: HashCache::new(cache_file, max_entries),
        }
    }

    /// Load cache from persistent storage
    pub async fn load_cache(&mut self) -> Result<()> {
        self.cache.load().await
    }

    /// Save cache to persistent storage
    pub async fn save_cache(&self) -> Result<()> {
        self.cache.save().await
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics (current entries, max entries)
    pub fn cache_stats(&self) -> (usize, usize) {
        self.cache.stats()
    }

    /// Compute hash for the entire file with concurrent modification checking
    pub async fn compute_hash(&mut self, file_path: &Path) -> Result<String> {
        // Check cache first
        if let Some(cached_hash) = self.cache.get(file_path, self.algorithm).await {
            return Ok(cached_hash);
        }

        // Compute hash if not in cache
        let hash = self.compute_hash_uncached(file_path).await?;
        
        // Store in cache
        self.cache.put(file_path.to_path_buf(), hash.clone(), self.algorithm).await?;
        
        Ok(hash)
    }

    /// Compute hash for a FileMetadata with concurrent modification checking
    pub async fn compute_hash_for_metadata(&mut self, file_metadata: &mut crate::models::FileMetadata) -> Result<String> {
        // Check if file has been modified since metadata was collected
        if file_metadata.check_if_modified().await? {
            eprintln!("Warning: File {} was modified during analysis, using current content", file_metadata.path.display());
            
            // Update metadata with current file information
            file_metadata.refresh_metadata().await?;
        }
        
        // Check cache first
        if let Some(cached_hash) = self.cache.get(&file_metadata.path, self.algorithm).await {
            return Ok(cached_hash);
        }

        // Compute hash if not in cache
        let hash = self.compute_hash_uncached(&file_metadata.path).await?;
        
        // Store in cache
        self.cache.put(file_metadata.path.clone(), hash.clone(), self.algorithm).await?;
        
        // Update the file metadata with the computed hash
        file_metadata.set_hash(hash.clone());
        
        Ok(hash)
    }

    /// Compute hash without using cache
    async fn compute_hash_uncached(&self, file_path: &Path) -> Result<String> {
        let file = File::open(file_path).await?;
        let mut reader = BufReader::new(file);
        
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 8192]; // 8KB buffer for streaming
                
                loop {
                    let bytes_read = reader.read(&mut buffer).await?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                
                let result = hasher.finalize();
                Ok(format!("{:x}", result))
            }
            HashAlgorithm::Md5 => {
                let mut hasher = md5::Context::new();
                let mut buffer = [0u8; 8192]; // 8KB buffer for streaming
                
                loop {
                    let bytes_read = reader.read(&mut buffer).await?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.consume(&buffer[..bytes_read]);
                }
                
                let result = hasher.compute();
                Ok(format!("{:x}", result))
            }
        }
    }

    /// Compute partial hash for the first N bytes of a file
    pub async fn compute_partial_hash(&mut self, file_path: &Path, bytes: u64) -> Result<String> {
        // Note: Partial hashes are not cached as they depend on the byte count parameter
        self.compute_partial_hash_uncached(file_path, bytes).await
    }

    /// Compute partial hash without using cache
    async fn compute_partial_hash_uncached(&self, file_path: &Path, bytes: u64) -> Result<String> {
        let file = File::open(file_path).await?;
        let mut reader = BufReader::new(file);
        
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 8192]; // 8KB buffer for streaming
                let mut bytes_remaining = bytes;
                
                while bytes_remaining > 0 {
                    let bytes_to_read = std::cmp::min(buffer.len() as u64, bytes_remaining) as usize;
                    let bytes_read = reader.read(&mut buffer[..bytes_to_read]).await?;
                    if bytes_read == 0 {
                        break; // EOF reached
                    }
                    hasher.update(&buffer[..bytes_read]);
                    bytes_remaining -= bytes_read as u64;
                }
                
                let result = hasher.finalize();
                Ok(format!("{:x}", result))
            }
            HashAlgorithm::Md5 => {
                let mut hasher = md5::Context::new();
                let mut buffer = [0u8; 8192]; // 8KB buffer for streaming
                let mut bytes_remaining = bytes;
                
                while bytes_remaining > 0 {
                    let bytes_to_read = std::cmp::min(buffer.len() as u64, bytes_remaining) as usize;
                    let bytes_read = reader.read(&mut buffer[..bytes_to_read]).await?;
                    if bytes_read == 0 {
                        break; // EOF reached
                    }
                    hasher.consume(&buffer[..bytes_read]);
                    bytes_remaining -= bytes_read as u64;
                }
                
                let result = hasher.compute();
                Ok(format!("{:x}", result))
            }
        }
    }

    /// Set the hash algorithm
    pub fn set_algorithm(&mut self, algorithm: HashAlgorithm) {
        self.algorithm = algorithm;
    }

    /// Get the current hash algorithm
    pub fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

impl Default for HashComputer {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    // Property-based test generators
    prop_compose! {
        fn arb_file_content()(
            content in prop::collection::vec(any::<u8>(), 0..10000)
        ) -> Vec<u8> {
            content
        }
    }

    prop_compose! {
        fn arb_hash_algorithm()(
            algo in prop::sample::select(vec![HashAlgorithm::Sha256, HashAlgorithm::Md5])
        ) -> HashAlgorithm {
            algo
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: duplicate-file-analyzer, Property 4: Correct Duplicate Grouping**
        /// **Validates: Requirements 2.4**
        /// For any files with identical content hashes, they should be grouped together as a duplicate set
        #[test]
        fn test_identical_content_produces_identical_hashes(
            content in arb_file_content(),
            algorithm in arb_hash_algorithm()
        ) {
            tokio_test::block_on(async {
                // Create two temporary files with identical content
                let mut file1 = NamedTempFile::new().unwrap();
                let mut file2 = NamedTempFile::new().unwrap();
                
                file1.write_all(&content).unwrap();
                file2.write_all(&content).unwrap();
                file1.flush().unwrap();
                file2.flush().unwrap();
                
                let mut computer = HashComputer::new(algorithm);
                
                // Compute hashes for both files
                let hash1 = computer.compute_hash(file1.path()).await.unwrap();
                let hash2 = computer.compute_hash(file2.path()).await.unwrap();
                
                // Property: Identical content should produce identical hashes
                assert_eq!(hash1, hash2);
                
                // Property: Hash should be non-empty for any content
                assert!(!hash1.is_empty());
                assert!(!hash2.is_empty());
                
                // Property: Hash should be deterministic (compute again and get same result)
                let hash1_again = computer.compute_hash_uncached(file1.path()).await.unwrap();
                assert_eq!(hash1, hash1_again);
            });
        }

        /// Test that different content produces different hashes (with high probability)
        #[test]
        fn test_different_content_produces_different_hashes(
            content1 in arb_file_content(),
            content2 in arb_file_content(),
            algorithm in arb_hash_algorithm()
        ) {
            // Skip if contents are identical
            prop_assume!(content1 != content2);
            
            tokio_test::block_on(async {
                let mut file1 = NamedTempFile::new().unwrap();
                let mut file2 = NamedTempFile::new().unwrap();
                
                file1.write_all(&content1).unwrap();
                file2.write_all(&content2).unwrap();
                file1.flush().unwrap();
                file2.flush().unwrap();
                
                let mut computer = HashComputer::new(algorithm);
                
                let hash1 = computer.compute_hash(file1.path()).await.unwrap();
                let hash2 = computer.compute_hash(file2.path()).await.unwrap();
                
                // Property: Different content should produce different hashes (with very high probability)
                // Note: This could theoretically fail due to hash collisions, but probability is negligible
                assert_ne!(hash1, hash2);
            });
        }

        /// Test hash caching behavior
        #[test]
        fn test_hash_caching_consistency(
            content in arb_file_content(),
            algorithm in arb_hash_algorithm()
        ) {
            tokio_test::block_on(async {
                let mut file = NamedTempFile::new().unwrap();
                file.write_all(&content).unwrap();
                file.flush().unwrap();
                
                let mut computer = HashComputer::new(algorithm);
                
                // First computation (not cached)
                let hash1 = computer.compute_hash(file.path()).await.unwrap();
                
                // Second computation (should be cached)
                let hash2 = computer.compute_hash(file.path()).await.unwrap();
                
                // Property: Cached hash should be identical to computed hash
                assert_eq!(hash1, hash2);
                
                // Property: Cache should contain the entry
                let (cache_size, _) = computer.cache_stats();
                assert!(cache_size > 0);
            });
        }

        /// Test partial hash computation
        #[test]
        fn test_partial_hash_properties(
            content in arb_file_content(),
            algorithm in arb_hash_algorithm()
        ) {
            // Only test if content is not empty
            prop_assume!(!content.is_empty());
            
            tokio_test::block_on(async {
                let mut file = NamedTempFile::new().unwrap();
                file.write_all(&content).unwrap();
                file.flush().unwrap();
                
                let mut computer = HashComputer::new(algorithm);
                
                let partial_bytes = std::cmp::min(content.len() as u64, 100);
                let partial_hash = computer.compute_partial_hash(file.path(), partial_bytes).await.unwrap();
                
                // Property: Partial hash should be non-empty
                assert!(!partial_hash.is_empty());
                
                // Property: Partial hash should be deterministic
                let partial_hash2 = computer.compute_partial_hash(file.path(), partial_bytes).await.unwrap();
                assert_eq!(partial_hash, partial_hash2);
                
                // Property: If we read the entire file as partial, it should match full hash
                if partial_bytes >= content.len() as u64 {
                    let full_hash = computer.compute_hash_uncached(file.path()).await.unwrap();
                    assert_eq!(partial_hash, full_hash);
                }
            });
        }
    }

    #[tokio::test]
    async fn test_hash_computer_basic_functionality() {
        let mut computer = HashComputer::new(HashAlgorithm::Sha256);
        
        // Create a test file
        let mut file = NamedTempFile::new().unwrap();
        let content = b"Hello, World!";
        file.write_all(content).unwrap();
        file.flush().unwrap();
        
        // Test hash computation
        let hash = computer.compute_hash(file.path()).await.unwrap();
        assert!(!hash.is_empty());
        
        // Test that the same content produces the same hash
        let hash2 = computer.compute_hash(file.path()).await.unwrap();
        assert_eq!(hash, hash2);
        
        // Test partial hash
        let partial_hash = computer.compute_partial_hash(file.path(), 5).await.unwrap();
        assert!(!partial_hash.is_empty());
        
        // Test cache functionality
        let (cache_size, max_size) = computer.cache_stats();
        assert!(cache_size > 0);
        assert!(max_size > 0);
        
        computer.clear_cache();
        let (cache_size_after_clear, _) = computer.cache_stats();
        assert_eq!(cache_size_after_clear, 0);
    }

    #[tokio::test]
    async fn test_hash_cache_persistence() {
        let cache_file = NamedTempFile::new().unwrap();
        let cache_path = cache_file.path().to_path_buf();
        
        // Create computer with persistent cache
        let mut computer = HashComputer::with_cache(HashAlgorithm::Sha256, Some(cache_path.clone()), 100);
        
        // Create a test file and compute hash
        let mut test_file = NamedTempFile::new().unwrap();
        test_file.write_all(b"test content").unwrap();
        test_file.flush().unwrap();
        
        let hash = computer.compute_hash(test_file.path()).await.unwrap();
        
        // Save cache
        computer.save_cache().await.unwrap();
        
        // Create new computer and load cache
        let mut computer2 = HashComputer::with_cache(HashAlgorithm::Sha256, Some(cache_path), 100);
        computer2.load_cache().await.unwrap();
        
        // Should get the same hash from cache
        let cached_hash = computer2.compute_hash(test_file.path()).await.unwrap();
        assert_eq!(hash, cached_hash);
    }

    #[tokio::test]
    async fn test_different_algorithms() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();
        file.flush().unwrap();
        
        let mut sha_computer = HashComputer::new(HashAlgorithm::Sha256);
        let mut md5_computer = HashComputer::new(HashAlgorithm::Md5);
        
        let sha_hash = sha_computer.compute_hash(file.path()).await.unwrap();
        let md5_hash = md5_computer.compute_hash(file.path()).await.unwrap();
        
        // Different algorithms should produce different hashes
        assert_ne!(sha_hash, md5_hash);
        
        // SHA-256 hash should be longer than MD5 hash
        assert!(sha_hash.len() > md5_hash.len());
    }
}
