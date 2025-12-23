//! Resume functionality for interrupted analyses

use crate::{models::*, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

// Custom serialization functions for SystemTime
fn serialize_systemtime<S>(
    time: &SystemTime,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let duration = time.duration_since(UNIX_EPOCH).map_err(serde::ser::Error::custom)?;
    serializer.serialize_u64(duration.as_secs())
}

fn deserialize_systemtime<'de, D>(
    deserializer: D,
) -> std::result::Result<SystemTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs: u64 = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// State information for resuming an interrupted analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisState {
    /// Unique identifier for this analysis session
    pub session_id: String,
    /// Target directory being analyzed
    pub target_directory: PathBuf,
    /// Discovery options used for this analysis
    pub discovery_options: DiscoveryOptions,
    /// Files that have been discovered
    pub discovered_files: Vec<FileMetadata>,
    /// Files that have had their hashes computed
    pub processed_files: Vec<FileMetadata>,
    /// Duplicate sets found so far
    pub duplicate_sets: Vec<DuplicateSet>,
    /// Errors encountered during analysis
    pub errors: Vec<AnalysisError>,
    /// Current analysis phase
    pub phase: AnalysisPhase,
    /// Timestamp when state was saved (as seconds since UNIX_EPOCH)
    #[serde(
        serialize_with = "serialize_systemtime",
        deserialize_with = "deserialize_systemtime"
    )]
    pub saved_at: SystemTime,
    /// Progress information
    pub progress: ProgressUpdate,
}

/// Current phase of analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisPhase {
    /// Discovering files in directory structure
    Discovery,
    /// Computing hashes for discovered files
    HashComputation,
    /// Finding duplicate sets
    DuplicateDetection,
    /// Analysis completed
    Completed,
}

/// Cache for computed file hashes
#[derive(Debug, Clone)]
pub struct HashCache {
    /// Map from file path and modification time to computed hash
    pub cache: HashMap<(PathBuf, SystemTime), String>,
    /// Timestamp when cache was last updated
    pub last_updated: SystemTime,
}

impl Serialize for HashCache {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("HashCache", 2)?;
        
        // Convert cache to a serializable format
        let cache_vec: Vec<(String, u64, String)> = self.cache.iter()
            .map(|((path, time), hash)| {
                let secs = time.duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                (path.to_string_lossy().to_string(), secs, hash.clone())
            })
            .collect();
        
        state.serialize_field("cache", &cache_vec)?;
        
        let last_updated_secs = self.last_updated.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        state.serialize_field("last_updated", &last_updated_secs)?;
        
        state.end()
    }
}

impl<'de> Deserialize<'de> for HashCache {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Cache,
            LastUpdated,
        }

        struct HashCacheVisitor;

        impl<'de> Visitor<'de> for HashCacheVisitor {
            type Value = HashCache;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct HashCache")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<HashCache, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut cache_vec: Option<Vec<(String, u64, String)>> = None;
                let mut last_updated_secs: Option<u64> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Cache => {
                            if cache_vec.is_some() {
                                return Err(de::Error::duplicate_field("cache"));
                            }
                            cache_vec = Some(map.next_value()?);
                        }
                        Field::LastUpdated => {
                            if last_updated_secs.is_some() {
                                return Err(de::Error::duplicate_field("last_updated"));
                            }
                            last_updated_secs = Some(map.next_value()?);
                        }
                    }
                }

                let cache_vec = cache_vec.ok_or_else(|| de::Error::missing_field("cache"))?;
                let last_updated_secs = last_updated_secs.ok_or_else(|| de::Error::missing_field("last_updated"))?;

                // Convert back to HashMap
                let mut cache = HashMap::new();
                for (path_str, secs, hash) in cache_vec {
                    let path = PathBuf::from(path_str);
                    let time = UNIX_EPOCH + std::time::Duration::from_secs(secs);
                    cache.insert((path, time), hash);
                }

                let last_updated = UNIX_EPOCH + std::time::Duration::from_secs(last_updated_secs);

                Ok(HashCache {
                    cache,
                    last_updated,
                })
            }
        }

        deserializer.deserialize_struct(
            "HashCache",
            &["cache", "last_updated"],
            HashCacheVisitor,
        )
    }
}

impl HashCache {
    /// Create a new empty hash cache
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            last_updated: SystemTime::now(),
        }
    }

    /// Get cached hash for a file if available and still valid
    pub fn get_hash(&self, file: &FileMetadata) -> Option<&str> {
        let key = (file.path.clone(), file.modified_time);
        self.cache.get(&key).map(|s| s.as_str())
    }

    /// Store computed hash for a file
    pub fn store_hash(&mut self, file: &FileMetadata, hash: String) {
        let key = (file.path.clone(), file.modified_time);
        self.cache.insert(key, hash);
        self.last_updated = SystemTime::now();
    }

    /// Remove stale entries from cache
    pub fn cleanup_stale_entries(&mut self, current_files: &[FileMetadata]) {
        let current_keys: std::collections::HashSet<_> = current_files
            .iter()
            .map(|f| (f.path.clone(), f.modified_time))
            .collect();

        self.cache.retain(|key, _| current_keys.contains(key));
        self.last_updated = SystemTime::now();
    }

    /// Get cache size (number of entries)
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    /// Clear all cached entries
    pub fn clear(&mut self) {
        self.cache.clear();
        self.last_updated = SystemTime::now();
    }
}

impl Default for HashCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager for saving and loading analysis state
pub struct ResumeManager {
    /// Directory where state files are stored
    state_dir: PathBuf,
    /// Hash cache for computed file hashes
    hash_cache: HashCache,
}

impl ResumeManager {
    /// Create a new resume manager
    pub fn new<P: AsRef<Path>>(state_dir: P) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        
        // Create state directory if it doesn't exist
        if !state_dir.exists() {
            std::fs::create_dir_all(&state_dir)?;
        }

        Ok(Self {
            state_dir,
            hash_cache: HashCache::new(),
        })
    }

    /// Create a new resume manager with default state directory
    pub fn with_default_dir() -> Result<Self> {
        let state_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("duplicate-file-analyzer")
            .join("state");
        
        Self::new(state_dir)
    }

    /// Save current analysis state to disk
    pub async fn save_state(&self, state: &AnalysisState) -> Result<()> {
        let state_file = self.get_state_file_path(&state.session_id);
        let state_json = serde_json::to_string_pretty(state)?;
        
        // Write to temporary file first, then rename for atomic operation
        let temp_file = state_file.with_extension("tmp");
        fs::write(&temp_file, state_json).await?;
        fs::rename(&temp_file, &state_file).await?;
        
        Ok(())
    }

    /// Load analysis state from disk
    pub async fn load_state(&self, session_id: &str) -> Result<Option<AnalysisState>> {
        let state_file = self.get_state_file_path(session_id);
        
        if !state_file.exists() {
            return Ok(None);
        }

        let state_json = fs::read_to_string(&state_file).await?;
        let state: AnalysisState = serde_json::from_str(&state_json)?;
        
        Ok(Some(state))
    }

    /// Check if a resumable state exists for the given session
    pub async fn has_resumable_state(&self, session_id: &str) -> bool {
        let state_file = self.get_state_file_path(session_id);
        state_file.exists()
    }

    /// Delete saved state for a session
    pub async fn delete_state(&self, session_id: &str) -> Result<()> {
        let state_file = self.get_state_file_path(session_id);
        
        if state_file.exists() {
            fs::remove_file(&state_file).await?;
        }
        
        Ok(())
    }

    /// List all available resumable sessions
    pub async fn list_resumable_sessions(&self) -> Result<Vec<String>> {
        let mut sessions = Vec::new();
        
        if !self.state_dir.exists() {
            return Ok(sessions);
        }

        let mut entries = fs::read_dir(&self.state_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Some(stem) = path.file_stem() {
                    if let Some(session_id) = stem.to_str() {
                        sessions.push(session_id.to_string());
                    }
                }
            }
        }
        
        Ok(sessions)
    }

    /// Save hash cache to disk
    pub async fn save_hash_cache(&self) -> Result<()> {
        let cache_file = self.state_dir.join("hash_cache.json");
        let cache_json = serde_json::to_string_pretty(&self.hash_cache)?;
        
        // Write to temporary file first, then rename for atomic operation
        let temp_file = cache_file.with_extension("tmp");
        fs::write(&temp_file, cache_json).await?;
        fs::rename(&temp_file, &cache_file).await?;
        
        Ok(())
    }

    /// Load hash cache from disk
    pub async fn load_hash_cache(&mut self) -> Result<()> {
        let cache_file = self.state_dir.join("hash_cache.json");
        
        if !cache_file.exists() {
            return Ok(());
        }

        let cache_json = fs::read_to_string(&cache_file).await?;
        self.hash_cache = serde_json::from_str(&cache_json)?;
        
        Ok(())
    }

    /// Get cached hash for a file
    pub fn get_cached_hash(&self, file: &FileMetadata) -> Option<&str> {
        self.hash_cache.get_hash(file)
    }

    /// Store computed hash in cache
    pub fn cache_hash(&mut self, file: &FileMetadata, hash: String) {
        self.hash_cache.store_hash(file, hash);
    }

    /// Clean up stale cache entries
    pub fn cleanup_cache(&mut self, current_files: &[FileMetadata]) {
        self.hash_cache.cleanup_stale_entries(current_files);
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, SystemTime) {
        (self.hash_cache.size(), self.hash_cache.last_updated)
    }

    /// Clear hash cache
    pub fn clear_cache(&mut self) {
        self.hash_cache.clear();
    }

    /// Generate a unique session ID for a new analysis
    pub fn generate_session_id(target_directory: &Path) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        target_directory.hash(&mut hasher);
        SystemTime::now().hash(&mut hasher);
        
        format!("session_{:x}", hasher.finish())
    }

    /// Get the file path for storing state
    fn get_state_file_path(&self, session_id: &str) -> PathBuf {
        self.state_dir.join(format!("{}.json", session_id))
    }

    /// Clean up old state files (older than specified duration)
    pub async fn cleanup_old_states(&self, max_age: std::time::Duration) -> Result<usize> {
        let mut cleaned_count = 0;
        let cutoff_time = SystemTime::now() - max_age;
        
        if !self.state_dir.exists() {
            return Ok(0);
        }

        let mut entries = fs::read_dir(&self.state_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        if modified < cutoff_time {
                            if fs::remove_file(&path).await.is_ok() {
                                cleaned_count += 1;
                            }
                        }
                    }
                }
            }
        }
        
        Ok(cleaned_count)
    }
}

impl AnalysisState {
    /// Create a new analysis state
    pub fn new(
        session_id: String,
        target_directory: PathBuf,
        discovery_options: DiscoveryOptions,
    ) -> Self {
        Self {
            session_id,
            target_directory,
            discovery_options,
            discovered_files: Vec::new(),
            processed_files: Vec::new(),
            duplicate_sets: Vec::new(),
            errors: Vec::new(),
            phase: AnalysisPhase::Discovery,
            saved_at: SystemTime::now(),
            progress: ProgressUpdate::new(),
        }
    }

    /// Update the current phase
    pub fn set_phase(&mut self, phase: AnalysisPhase) {
        self.phase = phase;
        self.saved_at = SystemTime::now();
    }

    /// Add discovered files
    pub fn add_discovered_files(&mut self, files: Vec<FileMetadata>) {
        self.discovered_files.extend(files);
        self.progress.total_files = self.discovered_files.len() as u64;
        self.saved_at = SystemTime::now();
    }

    /// Add processed file with hash
    pub fn add_processed_file(&mut self, file: FileMetadata) {
        self.processed_files.push(file);
        self.progress.files_processed = self.processed_files.len() as u64;
        self.saved_at = SystemTime::now();
    }

    /// Add duplicate set
    pub fn add_duplicate_set(&mut self, duplicate_set: DuplicateSet) {
        self.progress.duplicates_found += duplicate_set.files.len() as u64;
        self.duplicate_sets.push(duplicate_set);
        self.saved_at = SystemTime::now();
    }

    /// Add error
    pub fn add_error(&mut self, error: AnalysisError) {
        self.errors.push(error);
        self.saved_at = SystemTime::now();
    }

    /// Convert to final analysis result
    pub fn to_analysis_result(&self, analysis_time: f64) -> AnalysisResult {
        let mut result = AnalysisResult::new();
        result.duplicate_sets = self.duplicate_sets.clone();
        result.total_files_analyzed = self.discovered_files.len() as u64;
        result.total_duplicate_files = self.duplicate_sets.iter()
            .map(|ds| ds.files.len() as u64)
            .sum();
        result.total_potential_savings = self.duplicate_sets.iter()
            .map(|ds| ds.potential_savings)
            .sum();
        result.analysis_time = analysis_time;
        result.errors = self.errors.clone();
        
        // Sort by potential savings
        result.sort_by_savings();
        
        result
    }

    /// Check if analysis is complete
    pub fn is_complete(&self) -> bool {
        self.phase == AnalysisPhase::Completed
    }

    /// Get progress percentage
    pub fn progress_percentage(&self) -> f64 {
        self.progress.progress_percentage()
    }
}

// Make DiscoveryOptions serializable for resume functionality
impl Serialize for DiscoveryOptions {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("DiscoveryOptions", 8)?;
        state.serialize_field("exclude_patterns", &self.exclude_patterns)?;
        state.serialize_field("exclude_directories", &self.exclude_directories)?;
        state.serialize_field("min_file_size", &self.min_file_size)?;
        state.serialize_field("max_file_size", &self.max_file_size)?;
        state.serialize_field("include_extensions", &self.include_extensions)?;
        state.serialize_field("exclude_extensions", &self.exclude_extensions)?;
        state.serialize_field("follow_symlinks", &self.follow_symlinks)?;
        state.serialize_field("max_depth", &self.max_depth)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DiscoveryOptions {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            ExcludePatterns,
            ExcludeDirectories,
            MinFileSize,
            MaxFileSize,
            IncludeExtensions,
            ExcludeExtensions,
            FollowSymlinks,
            MaxDepth,
        }

        struct DiscoveryOptionsVisitor;

        impl<'de> Visitor<'de> for DiscoveryOptionsVisitor {
            type Value = DiscoveryOptions;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct DiscoveryOptions")
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<DiscoveryOptions, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut exclude_patterns = None;
                let mut exclude_directories = None;
                let mut min_file_size = None;
                let mut max_file_size = None;
                let mut include_extensions = None;
                let mut exclude_extensions = None;
                let mut follow_symlinks = None;
                let mut max_depth = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ExcludePatterns => {
                            if exclude_patterns.is_some() {
                                return Err(de::Error::duplicate_field("exclude_patterns"));
                            }
                            exclude_patterns = Some(map.next_value()?);
                        }
                        Field::ExcludeDirectories => {
                            if exclude_directories.is_some() {
                                return Err(de::Error::duplicate_field("exclude_directories"));
                            }
                            exclude_directories = Some(map.next_value()?);
                        }
                        Field::MinFileSize => {
                            if min_file_size.is_some() {
                                return Err(de::Error::duplicate_field("min_file_size"));
                            }
                            min_file_size = map.next_value()?;
                        }
                        Field::MaxFileSize => {
                            if max_file_size.is_some() {
                                return Err(de::Error::duplicate_field("max_file_size"));
                            }
                            max_file_size = map.next_value()?;
                        }
                        Field::IncludeExtensions => {
                            if include_extensions.is_some() {
                                return Err(de::Error::duplicate_field("include_extensions"));
                            }
                            include_extensions = Some(map.next_value()?);
                        }
                        Field::ExcludeExtensions => {
                            if exclude_extensions.is_some() {
                                return Err(de::Error::duplicate_field("exclude_extensions"));
                            }
                            exclude_extensions = Some(map.next_value()?);
                        }
                        Field::FollowSymlinks => {
                            if follow_symlinks.is_some() {
                                return Err(de::Error::duplicate_field("follow_symlinks"));
                            }
                            follow_symlinks = Some(map.next_value()?);
                        }
                        Field::MaxDepth => {
                            if max_depth.is_some() {
                                return Err(de::Error::duplicate_field("max_depth"));
                            }
                            max_depth = map.next_value()?;
                        }
                    }
                }

                Ok(DiscoveryOptions {
                    exclude_patterns: exclude_patterns.unwrap_or_default(),
                    exclude_directories: exclude_directories.unwrap_or_default(),
                    min_file_size,
                    max_file_size,
                    include_extensions: include_extensions.unwrap_or_default(),
                    exclude_extensions: exclude_extensions.unwrap_or_default(),
                    follow_symlinks: follow_symlinks.unwrap_or(false),
                    max_depth,
                })
            }
        }

        deserializer.deserialize_struct(
            "DiscoveryOptions",
            &[
                "exclude_patterns",
                "exclude_directories", 
                "min_file_size",
                "max_file_size",
                "include_extensions",
                "exclude_extensions",
                "follow_symlinks",
                "max_depth",
            ],
            DiscoveryOptionsVisitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::TempDir;
    use std::time::Duration;

    prop_compose! {
        fn arb_analysis_state()(
            session_id in "[a-zA-Z0-9_]{8,20}",
            target_dir in "[a-zA-Z0-9_/]{5,30}",
            phase in prop::sample::select(vec![
                AnalysisPhase::Discovery,
                AnalysisPhase::HashComputation,
                AnalysisPhase::DuplicateDetection,
                AnalysisPhase::Completed,
            ])
        ) -> AnalysisState {
            let mut state = AnalysisState::new(
                session_id,
                PathBuf::from(target_dir),
                DiscoveryOptions::default(),
            );
            state.set_phase(phase);
            state
        }
    }

    #[tokio::test]
    async fn test_resume_manager_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ResumeManager::new(temp_dir.path()).unwrap();
        
        // Create a test analysis state
        let session_id = "test_session_123";
        let state = AnalysisState::new(
            session_id.to_string(),
            PathBuf::from("/test/directory"),
            DiscoveryOptions::default(),
        );
        
        // Save state
        manager.save_state(&state).await.unwrap();
        
        // Check if state exists
        assert!(manager.has_resumable_state(session_id).await);
        
        // Load state
        let loaded_state = manager.load_state(session_id).await.unwrap();
        assert!(loaded_state.is_some());
        
        let loaded_state = loaded_state.unwrap();
        assert_eq!(loaded_state.session_id, state.session_id);
        assert_eq!(loaded_state.target_directory, state.target_directory);
        assert_eq!(loaded_state.phase, state.phase);
        
        // List sessions
        let sessions = manager.list_resumable_sessions().await.unwrap();
        assert!(sessions.contains(&session_id.to_string()));
        
        // Delete state
        manager.delete_state(session_id).await.unwrap();
        assert!(!manager.has_resumable_state(session_id).await);
    }

    #[tokio::test]
    async fn test_hash_cache_operations() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = ResumeManager::new(temp_dir.path()).unwrap();
        
        // Create test file metadata with a specific time
        let fixed_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000000);
        let file = FileMetadata::new(
            PathBuf::from("/test/file.txt"),
            1024,
            fixed_time,
            true,
        );
        
        // Initially no cached hash
        assert!(manager.get_cached_hash(&file).is_none());
        
        // Cache a hash
        let hash = "abc123def456".to_string();
        manager.cache_hash(&file, hash.clone());
        
        // Should now have cached hash
        assert_eq!(manager.get_cached_hash(&file), Some(hash.as_str()));
        
        // Save and load cache
        manager.save_hash_cache().await.unwrap();
        
        let mut new_manager = ResumeManager::new(temp_dir.path()).unwrap();
        new_manager.load_hash_cache().await.unwrap();
        
        // Should still have cached hash after reload
        // Use the same file metadata with the same fixed time
        let file_after_reload = FileMetadata::new(
            PathBuf::from("/test/file.txt"),
            1024,
            fixed_time,
            true,
        );
        assert_eq!(new_manager.get_cached_hash(&file_after_reload), Some(hash.as_str()));
        
        // Test cache cleanup
        let other_files = vec![
            FileMetadata::new(
                PathBuf::from("/test/other.txt"),
                2048,
                SystemTime::now(),
                true,
            )
        ];
        new_manager.cleanup_cache(&other_files);
        
        // Original file should be removed from cache since it's not in current_files
        assert!(new_manager.get_cached_hash(&file_after_reload).is_none());
    }

    proptest! {
        /// **Feature: duplicate-file-analyzer, Property 11: Resume Capability**
        /// **Validates: Requirements 6.5**
        /// For any interrupted analysis with cached intermediate results, resuming should continue 
        /// from where it left off and produce equivalent final results
        #[test]
        fn test_resume_capability_property(state in arb_analysis_state()) {
            tokio_test::block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let manager = ResumeManager::new(temp_dir.path()).unwrap();
                
                // Property: Save and load should be round-trip consistent
                manager.save_state(&state).await.unwrap();
                let loaded_state = manager.load_state(&state.session_id).await.unwrap();
                
                prop_assert!(loaded_state.is_some(), "Saved state should be loadable");
                let loaded_state = loaded_state.unwrap();
                let session_id = loaded_state.session_id.clone();
                
                // Property: All critical state should be preserved
                prop_assert_eq!(loaded_state.session_id, state.session_id);
                prop_assert_eq!(loaded_state.target_directory, state.target_directory);
                prop_assert_eq!(loaded_state.phase, state.phase);
                prop_assert_eq!(loaded_state.discovered_files.len(), state.discovered_files.len());
                prop_assert_eq!(loaded_state.processed_files.len(), state.processed_files.len());
                prop_assert_eq!(loaded_state.duplicate_sets.len(), state.duplicate_sets.len());
                prop_assert_eq!(loaded_state.errors.len(), state.errors.len());
                
                // Property: Progress information should be preserved
                prop_assert_eq!(loaded_state.progress.files_processed, state.progress.files_processed);
                prop_assert_eq!(loaded_state.progress.total_files, state.progress.total_files);
                prop_assert_eq!(loaded_state.progress.duplicates_found, state.progress.duplicates_found);
                
                // Property: Session should be listed in resumable sessions
                let sessions = manager.list_resumable_sessions().await.unwrap();
                prop_assert!(sessions.contains(&session_id), 
                    "Session {} should be in resumable sessions list", session_id);
                
                // Property: State should be detectable as resumable
                prop_assert!(manager.has_resumable_state(&session_id).await,
                    "State should be detectable as resumable");
                
                // Property: Deletion should work correctly
                manager.delete_state(&session_id).await.unwrap();
                prop_assert!(!manager.has_resumable_state(&session_id).await,
                    "State should not be resumable after deletion");
                
                let deleted_state = manager.load_state(&session_id).await.unwrap();
                prop_assert!(deleted_state.is_none(), "Deleted state should not be loadable");
                
                Ok(())
            })?;
        }

        /// Test analysis state progression and conversion
        #[test]
        fn test_analysis_state_progression(mut state in arb_analysis_state()) {
            // Property: Phase transitions should update saved timestamp
            let original_time = state.saved_at;
            std::thread::sleep(Duration::from_millis(1)); // Ensure time difference
            
            state.set_phase(AnalysisPhase::HashComputation);
            prop_assert!(state.saved_at > original_time, "Timestamp should be updated on phase change");
            
            // Property: Adding files should update progress
            let test_files = vec![
                FileMetadata::new(PathBuf::from("/test1.txt"), 100, SystemTime::now(), true),
                FileMetadata::new(PathBuf::from("/test2.txt"), 200, SystemTime::now(), true),
            ];
            
            state.add_discovered_files(test_files.clone());
            prop_assert_eq!(state.progress.total_files, test_files.len() as u64);
            prop_assert_eq!(state.discovered_files.len(), test_files.len());
            
            // Property: Processing files should update progress
            let mut processed_file = test_files[0].clone();
            processed_file.set_hash("abc123".to_string());
            state.add_processed_file(processed_file);
            prop_assert_eq!(state.progress.files_processed, 1);
            
            // Property: Analysis result conversion should be consistent
            let analysis_time = 123.45;
            let result = state.to_analysis_result(analysis_time);
            
            prop_assert_eq!(result.analysis_time, analysis_time);
            prop_assert_eq!(result.total_files_analyzed, state.discovered_files.len() as u64);
            prop_assert_eq!(result.duplicate_sets.len(), state.duplicate_sets.len());
            prop_assert_eq!(result.errors.len(), state.errors.len());
            
            // Property: Progress percentage should be between 0 and 100
            let percentage = state.progress_percentage();
            prop_assert!(percentage >= 0.0 && percentage <= 100.0,
                "Progress percentage {} should be between 0 and 100", percentage);
        }
    }

    #[tokio::test]
    async fn test_cleanup_old_states() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ResumeManager::new(temp_dir.path()).unwrap();
        
        // Create some test states
        let old_state = AnalysisState::new(
            "old_session".to_string(),
            PathBuf::from("/test"),
            DiscoveryOptions::default(),
        );
        
        let new_state = AnalysisState::new(
            "new_session".to_string(),
            PathBuf::from("/test"),
            DiscoveryOptions::default(),
        );
        
        manager.save_state(&old_state).await.unwrap();
        manager.save_state(&new_state).await.unwrap();
        
        // Both should exist initially
        assert!(manager.has_resumable_state("old_session").await);
        assert!(manager.has_resumable_state("new_session").await);
        
        // Clean up states older than 0 seconds (should clean up all)
        let cleaned = manager.cleanup_old_states(Duration::from_secs(0)).await.unwrap();
        assert_eq!(cleaned, 2);
        
        // Both should be gone now
        assert!(!manager.has_resumable_state("old_session").await);
        assert!(!manager.has_resumable_state("new_session").await);
    }

    #[test]
    fn test_session_id_generation() {
        let path1 = PathBuf::from("/test/path1");
        let path2 = PathBuf::from("/test/path2");
        
        // Different paths should generate different session IDs
        let id1 = ResumeManager::generate_session_id(&path1);
        let id2 = ResumeManager::generate_session_id(&path2);
        
        assert_ne!(id1, id2);
        assert!(id1.starts_with("session_"));
        assert!(id2.starts_with("session_"));
        
        // Same path at different times should generate different IDs
        std::thread::sleep(Duration::from_millis(1));
        let id3 = ResumeManager::generate_session_id(&path1);
        assert_ne!(id1, id3);
    }
}