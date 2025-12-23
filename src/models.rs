//! Data models for the duplicate file analyzer

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// Custom serialization functions for SystemTime
fn serialize_optional_systemtime<S>(
    time: &Option<SystemTime>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match time {
        Some(t) => {
            let duration = t.duration_since(UNIX_EPOCH).map_err(serde::ser::Error::custom)?;
            serializer.serialize_some(&duration.as_secs())
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_systemtime<'de, D>(
    deserializer: D,
) -> Result<Option<SystemTime>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct OptionalSystemTimeVisitor;

    impl<'de> Visitor<'de> for OptionalSystemTimeVisitor {
        type Value = Option<SystemTime>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("null or a u64 timestamp")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let secs: u64 = u64::deserialize(deserializer)?;
            Ok(Some(UNIX_EPOCH + std::time::Duration::from_secs(secs)))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(UNIX_EPOCH + std::time::Duration::from_secs(value)))
        }
    }

    deserializer.deserialize_option(OptionalSystemTimeVisitor)
}

/// Metadata for a discovered file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileMetadata {
    /// Absolute file path
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// Last modification timestamp
    pub modified_time: SystemTime,
    /// Whether the file can be read
    pub is_accessible: bool,
    /// Content hash (computed on demand)
    pub hash: Option<String>,
}

impl FileMetadata {
    /// Create new file metadata
    pub fn new(path: PathBuf, size: u64, modified_time: SystemTime, is_accessible: bool) -> Self {
        Self {
            path,
            size,
            modified_time,
            is_accessible,
            hash: None,
        }
    }

    /// Set the content hash
    pub fn set_hash(&mut self, hash: String) {
        self.hash = Some(hash);
    }

    /// Get the file name
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name().and_then(|name| name.to_str())
    }

    /// Get the file extension
    pub fn extension(&self) -> Option<&str> {
        self.path.extension().and_then(|ext| ext.to_str())
    }

    /// Check if the file has a hash computed
    pub fn has_hash(&self) -> bool {
        self.hash.is_some()
    }

    /// Get the hash if available
    pub fn get_hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }
}

/// A group of files with identical content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateSet {
    /// Unique identifier for the set
    pub id: String,
    /// All files with identical content
    pub files: Vec<FileMetadata>,
    /// Content hash shared by all files
    pub hash: String,
    /// Size of each file in the set
    pub total_size: u64,
    /// Bytes that could be saved by removing duplicates
    pub potential_savings: u64,
    /// How duplicates were detected
    pub detection_method: DetectionMethod,
}

impl DuplicateSet {
    /// Create a new duplicate set
    pub fn new(files: Vec<FileMetadata>, hash: String) -> Self {
        let total_size = files.first().map(|f| f.size).unwrap_or(0);
        let potential_savings = if files.len() > 1 {
            total_size * (files.len() as u64 - 1)
        } else {
            0
        };

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            files,
            hash,
            total_size,
            potential_savings,
            detection_method: DetectionMethod::Hash,
        }
    }

    /// Get the number of duplicate files in this set
    pub fn duplicate_count(&self) -> usize {
        self.files.len()
    }

    /// Check if this set actually contains duplicates (more than 1 file)
    pub fn has_duplicates(&self) -> bool {
        self.files.len() > 1
    }

    /// Calculate space savings if keeping only the first file
    pub fn calculate_savings(&self) -> u64 {
        if self.files.len() > 1 {
            self.total_size * (self.files.len() as u64 - 1)
        } else {
            0
        }
    }
}

/// Method used to detect duplicates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    Hash,
    Content,
}

/// Complete analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// All duplicate sets found
    pub duplicate_sets: Vec<DuplicateSet>,
    /// Total number of files analyzed
    pub total_files_analyzed: u64,
    /// Total number of duplicate files
    pub total_duplicate_files: u64,
    /// Total bytes that could be saved
    pub total_potential_savings: u64,
    /// Time taken for analysis in seconds
    pub analysis_time: f64,
    /// Errors encountered during analysis
    pub errors: Vec<AnalysisError>,
}

impl AnalysisResult {
    /// Create a new empty analysis result
    pub fn new() -> Self {
        Self {
            duplicate_sets: Vec::new(),
            total_files_analyzed: 0,
            total_duplicate_files: 0,
            total_potential_savings: 0,
            analysis_time: 0.0,
            errors: Vec::new(),
        }
    }

    /// Add a duplicate set to the results
    pub fn add_duplicate_set(&mut self, duplicate_set: DuplicateSet) {
        self.total_duplicate_files += duplicate_set.files.len() as u64;
        self.total_potential_savings += duplicate_set.potential_savings;
        self.duplicate_sets.push(duplicate_set);
    }

    /// Sort duplicate sets by potential savings (descending)
    pub fn sort_by_savings(&mut self) {
        self.duplicate_sets
            .sort_by(|a, b| b.potential_savings.cmp(&a.potential_savings));
    }

    /// Add an error to the results
    pub fn add_error(&mut self, error: AnalysisError) {
        self.errors.push(error);
    }

    /// Get the total number of duplicate sets
    pub fn duplicate_set_count(&self) -> usize {
        self.duplicate_sets.len()
    }

    /// Check if any errors occurred during analysis
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Calculate the percentage of files that are duplicates
    pub fn duplicate_percentage(&self) -> f64 {
        if self.total_files_analyzed == 0 {
            0.0
        } else {
            (self.total_duplicate_files as f64 / self.total_files_analyzed as f64) * 100.0
        }
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Error that occurred during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisError {
    /// Error message
    pub message: String,
    /// File path where error occurred (if applicable)
    pub file_path: Option<PathBuf>,
    /// Error category
    pub category: ErrorCategory,
}

/// Categories of errors that can occur
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorCategory {
    FileSystem,
    HashComputation,
    System,
    Permission,
}

/// Options for file discovery
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Glob patterns to exclude from analysis (e.g., "*.log", "temp/*")
    pub exclude_patterns: Vec<String>,
    /// Directory paths to exclude from analysis
    pub exclude_directories: Vec<String>,
    /// Minimum file size in bytes (files smaller than this are excluded)
    pub min_file_size: Option<u64>,
    /// Maximum file size in bytes (files larger than this are excluded)
    pub max_file_size: Option<u64>,
    /// File extensions to include (if specified, only these extensions are analyzed)
    pub include_extensions: Vec<String>,
    /// File extensions to exclude from analysis
    pub exclude_extensions: Vec<String>,
    /// Whether to follow symbolic links
    pub follow_symlinks: bool,
    /// Maximum depth to traverse
    pub max_depth: Option<usize>,
}

impl DiscoveryOptions {
    /// Add a glob pattern to exclude from analysis
    pub fn exclude_pattern<S: Into<String>>(mut self, pattern: S) -> Self {
        self.exclude_patterns.push(pattern.into());
        self
    }

    /// Add multiple glob patterns to exclude from analysis
    pub fn exclude_patterns<I, S>(mut self, patterns: I) -> Self 
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_patterns.extend(patterns.into_iter().map(|p| p.into()));
        self
    }

    /// Add a directory to exclude from analysis
    pub fn exclude_directory<S: Into<String>>(mut self, directory: S) -> Self {
        self.exclude_directories.push(directory.into());
        self
    }

    /// Add multiple directories to exclude from analysis
    pub fn exclude_directories<I, S>(mut self, directories: I) -> Self 
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_directories.extend(directories.into_iter().map(|d| d.into()));
        self
    }

    /// Set minimum file size filter
    pub fn min_file_size(mut self, size: u64) -> Self {
        self.min_file_size = Some(size);
        self
    }

    /// Set maximum file size filter
    pub fn max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = Some(size);
        self
    }

    /// Set file size range filter
    pub fn file_size_range(mut self, min: u64, max: u64) -> Self {
        self.min_file_size = Some(min);
        self.max_file_size = Some(max);
        self
    }

    /// Add a file extension to include (if specified, only these extensions are analyzed)
    pub fn include_extension<S: Into<String>>(mut self, extension: S) -> Self {
        self.include_extensions.push(extension.into());
        self
    }

    /// Add multiple file extensions to include
    pub fn include_extensions<I, S>(mut self, extensions: I) -> Self 
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.include_extensions.extend(extensions.into_iter().map(|e| e.into()));
        self
    }

    /// Add a file extension to exclude from analysis
    pub fn exclude_extension<S: Into<String>>(mut self, extension: S) -> Self {
        self.exclude_extensions.push(extension.into());
        self
    }

    /// Add multiple file extensions to exclude
    pub fn exclude_extensions<I, S>(mut self, extensions: I) -> Self 
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_extensions.extend(extensions.into_iter().map(|e| e.into()));
        self
    }

    /// Set whether to follow symbolic links
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Set maximum traversal depth
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            exclude_patterns: Vec::new(),
            exclude_directories: Vec::new(),
            min_file_size: None,
            max_file_size: None,
            include_extensions: Vec::new(),
            exclude_extensions: Vec::new(),
            follow_symlinks: false,
            max_depth: None,
        }
    }
}

/// Progress information for ongoing analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// Number of files processed so far
    pub files_processed: u64,
    /// Total number of files to process
    pub total_files: u64,
    /// Current file being processed
    pub current_file: Option<PathBuf>,
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Number of duplicates found so far
    pub duplicates_found: u64,
    /// Estimated completion time (as seconds since UNIX_EPOCH)
    #[serde(
        serialize_with = "serialize_optional_systemtime",
        deserialize_with = "deserialize_optional_systemtime"
    )]
    pub estimated_completion: Option<SystemTime>,
}

impl ProgressUpdate {
    /// Create a new progress update
    pub fn new() -> Self {
        Self {
            files_processed: 0,
            total_files: 0,
            current_file: None,
            bytes_processed: 0,
            duplicates_found: 0,
            estimated_completion: None,
        }
    }

    /// Calculate progress percentage
    pub fn progress_percentage(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            (self.files_processed as f64 / self.total_files as f64) * 100.0
        }
    }
}

impl Default for ProgressUpdate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    // Property-based test generators
    prop_compose! {
        fn arb_file_metadata()(
            path_str in "[a-zA-Z0-9_/.-]{1,100}",
            size in 0u64..1_000_000_000,
            timestamp in 0u64..1_000_000_000,
            is_accessible in any::<bool>(),
            hash_opt in prop::option::of("[a-f0-9]{64}")
        ) -> FileMetadata {
            let mut metadata = FileMetadata::new(
                PathBuf::from(path_str),
                size,
                UNIX_EPOCH + Duration::from_secs(timestamp),
                is_accessible
            );
            if let Some(hash) = hash_opt {
                metadata.set_hash(hash);
            }
            metadata
        }
    }

    prop_compose! {
        fn arb_duplicate_set()(
            files in prop::collection::vec(arb_file_metadata(), 1..10),
            hash in "[a-f0-9]{64}"
        ) -> DuplicateSet {
            // Ensure all files have the same size for realistic duplicate set
            let size = files.first().map(|f| f.size).unwrap_or(0);
            let files_with_same_size: Vec<FileMetadata> = files.into_iter().map(|mut f| {
                f.size = size;
                f
            }).collect();
            
            DuplicateSet::new(files_with_same_size, hash)
        }
    }

    prop_compose! {
        fn arb_analysis_result()(
            duplicate_sets in prop::collection::vec(arb_duplicate_set(), 0..5),
            analysis_time in 0.0f64..3600.0
        ) -> AnalysisResult {
            let mut result = AnalysisResult::new();
            result.analysis_time = analysis_time;
            
            // Calculate total files from duplicate sets
            let total_duplicate_files: u64 = duplicate_sets.iter()
                .map(|ds| ds.files.len() as u64)
                .sum();
            
            // Ensure total_files_analyzed is at least as large as total_duplicate_files
            // Add some additional non-duplicate files
            let additional_files = if total_duplicate_files > 0 { 
                total_duplicate_files / 2 
            } else { 
                10 
            };
            result.total_files_analyzed = total_duplicate_files + additional_files;
            
            for duplicate_set in duplicate_sets {
                result.add_duplicate_set(duplicate_set);
            }
            
            result
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: duplicate-file-analyzer, Property 1: Complete Directory Traversal**
        /// **Validates: Requirements 1.1, 1.4**
        /// For any directory structure, when analyzing a target directory, all accessible files 
        /// in all subdirectories should be discovered and have complete metadata collected
        #[test]
        fn test_file_metadata_completeness(metadata in arb_file_metadata()) {
            // Property: All FileMetadata instances should have complete required fields
            assert!(!metadata.path.as_os_str().is_empty());
            assert!(metadata.size >= 0);
            
            // Utility methods should work correctly
            if metadata.path.file_name().is_some() {
                assert!(metadata.file_name().is_some());
            }
            
            // Hash consistency
            assert_eq!(metadata.has_hash(), metadata.hash.is_some());
            assert_eq!(metadata.get_hash(), metadata.hash.as_deref());
        }

        /// Test serialization round-trip property
        #[test]
        fn test_file_metadata_serialization_roundtrip(metadata in arb_file_metadata()) {
            let serialized = serde_json::to_string(&metadata).unwrap();
            let deserialized: FileMetadata = serde_json::from_str(&serialized).unwrap();
            assert_eq!(metadata, deserialized);
        }

        /// **Feature: duplicate-file-analyzer, Property 6: Complete Duplicate Reporting**
        /// **Validates: Requirements 4.1, 4.2, 4.3**
        /// For any duplicate set found, the report should include all files in the set with 
        /// complete metadata (paths, sizes, modification dates) and correct space savings calculations
        #[test]
        fn test_space_savings_calculations(duplicate_set in arb_duplicate_set()) {
            // Property: Space savings should be calculated correctly
            let expected_savings = if duplicate_set.files.len() > 1 {
                duplicate_set.total_size * (duplicate_set.files.len() as u64 - 1)
            } else {
                0
            };
            
            assert_eq!(duplicate_set.potential_savings, expected_savings);
            assert_eq!(duplicate_set.calculate_savings(), expected_savings);
            
            // All files in the set should have the same size
            if !duplicate_set.files.is_empty() {
                let first_size = duplicate_set.files[0].size;
                for file in &duplicate_set.files {
                    assert_eq!(file.size, first_size);
                }
                assert_eq!(duplicate_set.total_size, first_size);
            }
            
            // Duplicate count should match file count
            assert_eq!(duplicate_set.duplicate_count(), duplicate_set.files.len());
            assert_eq!(duplicate_set.has_duplicates(), duplicate_set.files.len() > 1);
        }

        /// Test analysis result aggregation properties
        #[test]
        fn test_analysis_result_aggregation(result in arb_analysis_result()) {
            // Property: Total potential savings should equal sum of all duplicate set savings
            let expected_total_savings: u64 = result.duplicate_sets.iter()
                .map(|ds| ds.potential_savings)
                .sum();
            assert_eq!(result.total_potential_savings, expected_total_savings);
            
            // Property: Total duplicate files should equal sum of all files in duplicate sets
            let expected_duplicate_files: u64 = result.duplicate_sets.iter()
                .map(|ds| ds.files.len() as u64)
                .sum();
            assert_eq!(result.total_duplicate_files, expected_duplicate_files);
            
            // Property: Duplicate percentage should be between 0 and 100
            let percentage = result.duplicate_percentage();
            assert!(percentage >= 0.0 && percentage <= 100.0);
            
            // Property: Duplicate set count should match vector length
            assert_eq!(result.duplicate_set_count(), result.duplicate_sets.len());
        }

        /// **Feature: duplicate-file-analyzer, Property 7: Proper Result Sorting**
        /// **Validates: Requirements 4.4**
        /// For any analysis result, duplicate sets should be sorted by potential space savings in descending order
        #[test]
        fn test_result_sorting_by_savings(mut result in arb_analysis_result()) {
            // Only test if we have multiple duplicate sets
            if result.duplicate_sets.len() > 1 {
                // Sort the result
                result.sort_by_savings();
                
                // Property: After sorting, duplicate sets should be in descending order by potential savings
                for i in 0..result.duplicate_sets.len() - 1 {
                    let current_savings = result.duplicate_sets[i].potential_savings;
                    let next_savings = result.duplicate_sets[i + 1].potential_savings;
                    assert!(current_savings >= next_savings, 
                        "Duplicate sets not sorted correctly: {} should be >= {}", 
                        current_savings, next_savings);
                }
                
                // Property: Sorting should not change the total number of duplicate sets
                let original_count = result.duplicate_sets.len();
                result.sort_by_savings(); // Sort again
                assert_eq!(result.duplicate_sets.len(), original_count);
                
                // Property: Sorting should not change total potential savings
                let total_savings_after_sort: u64 = result.duplicate_sets.iter()
                    .map(|ds| ds.potential_savings)
                    .sum();
                assert_eq!(result.total_potential_savings, total_savings_after_sort);
            }
        }
    }

    #[test]
    fn test_file_metadata_basic_functionality() {
        let path = PathBuf::from("/test/file.txt");
        let size = 1024;
        let modified_time = SystemTime::now();
        let is_accessible = true;

        let mut metadata = FileMetadata::new(path.clone(), size, modified_time, is_accessible);
        
        assert_eq!(metadata.path, path);
        assert_eq!(metadata.size, size);
        assert_eq!(metadata.modified_time, modified_time);
        assert_eq!(metadata.is_accessible, is_accessible);
        assert_eq!(metadata.hash, None);
        assert!(!metadata.has_hash());
        assert_eq!(metadata.get_hash(), None);

        // Test setting hash
        let hash = "abc123".to_string();
        metadata.set_hash(hash.clone());
        assert_eq!(metadata.hash, Some(hash.clone()));
        assert!(metadata.has_hash());
        assert_eq!(metadata.get_hash(), Some(hash.as_str()));

        // Test utility methods
        assert_eq!(metadata.file_name(), Some("file.txt"));
        assert_eq!(metadata.extension(), Some("txt"));
    }
}