//! Duplicate detection engine for identifying identical files

use crate::{models::*, HashAlgorithm, Result, memory::MemoryMonitor};
use crate::hash::HashComputer;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Semaphore, Mutex};
use futures::stream::{self, StreamExt};

/// Groups files by size for efficient duplicate detection
/// This allows us to skip hash computation for files with unique sizes
pub struct SizeGrouper {
    /// Groups of files organized by size
    size_groups: HashMap<u64, Vec<FileMetadata>>,
}

impl SizeGrouper {
    /// Create a new size grouper
    pub fn new() -> Self {
        Self {
            size_groups: HashMap::new(),
        }
    }

    /// Group files by their size
    pub fn group_files(&mut self, files: Vec<FileMetadata>) -> &HashMap<u64, Vec<FileMetadata>> {
        self.size_groups.clear();
        
        for file in files {
            self.size_groups
                .entry(file.size)
                .or_insert_with(Vec::new)
                .push(file);
        }
        
        &self.size_groups
    }

    /// Get files that have potential duplicates (size groups with more than 1 file)
    pub fn get_potential_duplicates(&self) -> Vec<&Vec<FileMetadata>> {
        self.size_groups
            .values()
            .filter(|group| group.len() > 1)
            .collect()
    }

    /// Get files with unique sizes (no potential duplicates)
    pub fn get_unique_files(&self) -> Vec<&FileMetadata> {
        self.size_groups
            .values()
            .filter(|group| group.len() == 1)
            .flat_map(|group| group.iter())
            .collect()
    }

    /// Get the total number of size groups
    pub fn group_count(&self) -> usize {
        self.size_groups.len()
    }

    /// Get the number of groups that have potential duplicates
    pub fn potential_duplicate_groups(&self) -> usize {
        self.size_groups
            .values()
            .filter(|group| group.len() > 1)
            .count()
    }

    /// Get statistics about the grouping
    pub fn get_statistics(&self) -> SizeGroupingStats {
        let total_files: usize = self.size_groups.values().map(|group| group.len()).sum();
        let unique_files = self.get_unique_files().len();
        let potential_duplicates: usize = self.size_groups
            .values()
            .filter(|group| group.len() > 1)
            .map(|group| group.len())
            .sum();

        SizeGroupingStats {
            total_files,
            unique_files,
            potential_duplicates,
            size_groups: self.group_count(),
            duplicate_groups: self.potential_duplicate_groups(),
        }
    }

    /// Clear all grouped data
    pub fn clear(&mut self) {
        self.size_groups.clear();
    }
}

impl Default for SizeGrouper {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about size grouping results
#[derive(Debug, Clone)]
pub struct SizeGroupingStats {
    /// Total number of files processed
    pub total_files: usize,
    /// Number of files with unique sizes
    pub unique_files: usize,
    /// Number of files that could potentially be duplicates
    pub potential_duplicates: usize,
    /// Total number of size groups
    pub size_groups: usize,
    /// Number of groups with potential duplicates
    pub duplicate_groups: usize,
}

impl SizeGroupingStats {
    /// Calculate the percentage of files that could be duplicates
    pub fn potential_duplicate_percentage(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            (self.potential_duplicates as f64 / self.total_files as f64) * 100.0
        }
    }

    /// Calculate the efficiency gain from size-based filtering
    /// Returns the percentage of files that don't need hash computation
    pub fn efficiency_gain(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            (self.unique_files as f64 / self.total_files as f64) * 100.0
        }
    }
}

/// Matches files with identical content hashes to create duplicate sets
pub struct DuplicateMatcher {
    /// Hash computer for computing file content hashes
    hash_computer: Arc<Mutex<HashComputer>>,
    /// Semaphore to limit concurrent hash computations
    hash_semaphore: Arc<Semaphore>,
    /// Number of parallel hash computation tasks
    parallelism: usize,
}

impl DuplicateMatcher {
    /// Create a new duplicate matcher
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let parallelism = num_cpus::get();
        Self {
            hash_computer: Arc::new(Mutex::new(HashComputer::new(algorithm))),
            hash_semaphore: Arc::new(Semaphore::new(parallelism)),
            parallelism,
        }
    }

    /// Create a new duplicate matcher with custom parallelism
    pub fn with_parallelism(algorithm: HashAlgorithm, parallelism: usize) -> Self {
        Self {
            hash_computer: Arc::new(Mutex::new(HashComputer::new(algorithm))),
            hash_semaphore: Arc::new(Semaphore::new(parallelism)),
            parallelism,
        }
    }

    /// Find duplicate sets from groups of files with matching sizes using parallel processing
    pub async fn find_duplicate_sets(
        &mut self,
        size_groups: Vec<&Vec<FileMetadata>>,
    ) -> Result<Vec<DuplicateSet>> {
        let mut duplicate_sets = Vec::new();

        for size_group in size_groups {
            if size_group.len() <= 1 {
                // Skip groups with only one file - no duplicates possible
                continue;
            }

            // Filter out inaccessible files first
            let accessible_files: Vec<FileMetadata> = size_group
                .iter()
                .filter(|file| file.is_accessible)
                .cloned()
                .collect();

            if accessible_files.len() <= 1 {
                // Skip if no accessible files or only one accessible file
                continue;
            }

            // Compute hashes in parallel for all files in this size group
            let hash_results = self.compute_hashes_parallel(accessible_files).await?;

            // Group files by their computed hashes
            let mut hash_groups: HashMap<String, Vec<FileMetadata>> = HashMap::new();
            
            for (file, hash) in hash_results {
                hash_groups
                    .entry(hash)
                    .or_insert_with(Vec::new)
                    .push(file);
            }

            // Create duplicate sets for hash groups with more than one file
            for (hash, files) in hash_groups {
                if files.len() > 1 {
                    let duplicate_set = DuplicateSet::new(files, hash);
                    duplicate_sets.push(duplicate_set);
                }
            }
        }

        Ok(duplicate_sets)
    }

    /// Compute hashes for multiple files in parallel
    async fn compute_hashes_parallel(
        &self,
        files: Vec<FileMetadata>,
    ) -> Result<Vec<(FileMetadata, String)>> {
        let hash_computer = Arc::clone(&self.hash_computer);
        let semaphore = Arc::clone(&self.hash_semaphore);

        // Create a stream of hash computation tasks
        let hash_tasks = stream::iter(files.into_iter().map(|mut file| {
            let hash_computer = Arc::clone(&hash_computer);
            let semaphore = Arc::clone(&semaphore);
            
            async move {
                // Acquire semaphore permit to limit concurrent operations
                let _permit = semaphore.acquire().await.map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to acquire semaphore: {}", e)
                    )) as Box<dyn std::error::Error + Send + Sync>
                })?;

                // Compute hash with concurrent modification checking
                let mut hash_computer_guard = hash_computer.lock().await;
                let hash = hash_computer_guard.compute_hash_for_metadata(&mut file).await?;
                drop(hash_computer_guard); // Release lock early

                Ok::<(FileMetadata, String), Box<dyn std::error::Error + Send + Sync>>((file, hash))
            }
        }));

        // Execute hash computations with limited concurrency
        let results: Vec<Result<(FileMetadata, String)>> = hash_tasks
            .buffer_unordered(self.parallelism)
            .collect::<Vec<_>>()
            .await;

        // Collect successful results and handle errors
        let mut hash_results = Vec::new();
        for result in results {
            match result {
                Ok((file, hash)) => hash_results.push((file, hash)),
                Err(e) => {
                    eprintln!("Error computing hash: {}", e);
                    // Continue processing other files
                }
            }
        }

        Ok(hash_results)
    }

    /// Set the hash algorithm
    pub async fn set_algorithm(&mut self, algorithm: HashAlgorithm) {
        let mut hash_computer = self.hash_computer.lock().await;
        hash_computer.set_algorithm(algorithm);
    }

    /// Get the current hash algorithm
    pub async fn get_algorithm(&self) -> HashAlgorithm {
        let hash_computer = self.hash_computer.lock().await;
        hash_computer.get_algorithm()
    }

    /// Get hash computation cache statistics
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let hash_computer = self.hash_computer.lock().await;
        hash_computer.cache_stats()
    }

    /// Clear the hash cache
    pub async fn clear_cache(&mut self) {
        let mut hash_computer = self.hash_computer.lock().await;
        hash_computer.clear_cache();
    }

    /// Set the number of parallel hash computation tasks
    pub fn set_parallelism(&mut self, parallelism: usize) {
        self.parallelism = parallelism;
        self.hash_semaphore = Arc::new(Semaphore::new(parallelism));
    }

    /// Get the current parallelism setting
    pub fn get_parallelism(&self) -> usize {
        self.parallelism
    }
}

impl Default for DuplicateMatcher {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}

/// Engine for detecting duplicate files
pub struct DuplicateDetectionEngine {
    hash_algorithm: HashAlgorithm,
    thread_count: usize,
    size_grouper: SizeGrouper,
    duplicate_matcher: DuplicateMatcher,
    memory_monitor: MemoryMonitor,
}

impl DuplicateDetectionEngine {
    /// Create a new duplicate detection engine
    pub fn new() -> Self {
        let thread_count = num_cpus::get();
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            thread_count,
            size_grouper: SizeGrouper::new(),
            duplicate_matcher: DuplicateMatcher::with_parallelism(HashAlgorithm::Sha256, thread_count),
            memory_monitor: MemoryMonitor::default(),
        }
    }

    /// Create a new duplicate detection engine with custom thread count
    pub fn with_parallelism(thread_count: usize) -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            thread_count,
            size_grouper: SizeGrouper::new(),
            duplicate_matcher: DuplicateMatcher::with_parallelism(HashAlgorithm::Sha256, thread_count),
            memory_monitor: MemoryMonitor::default(),
        }
    }

    /// Create a new duplicate detection engine with custom memory settings
    pub fn with_memory_settings(thread_count: usize, max_memory: usize) -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            thread_count,
            size_grouper: SizeGrouper::new(),
            duplicate_matcher: DuplicateMatcher::with_parallelism(HashAlgorithm::Sha256, thread_count),
            memory_monitor: MemoryMonitor::new(max_memory),
        }
    }

    /// Find duplicates in the provided file list with memory-efficient processing
    pub async fn find_duplicates(
        &mut self,
        files: Vec<FileMetadata>,
    ) -> Result<Vec<DuplicateSet>> {
        // Start memory monitoring
        let _monitor_handle = self.memory_monitor.start_monitoring();

        // Estimate memory usage for the file list
        let file_list_memory = files.len() * std::mem::size_of::<FileMetadata>();
        self.memory_monitor.add_usage(file_list_memory);

        // Step 1: Group files by size for efficient processing
        self.size_grouper.group_files(files);
        
        // Get statistics about the grouping
        let stats = self.size_grouper.get_statistics();
        println!("Size grouping stats: {} total files, {} unique files ({}% efficiency gain), {} potential duplicates in {} groups", 
                 stats.total_files, 
                 stats.unique_files, 
                 stats.efficiency_gain(),
                 stats.potential_duplicates,
                 stats.duplicate_groups);

        // Step 2: Get groups that have potential duplicates (more than 1 file with same size)
        let potential_duplicate_groups = self.size_grouper.get_potential_duplicates();
        
        if potential_duplicate_groups.is_empty() {
            println!("No potential duplicates found - all files have unique sizes");
            self.memory_monitor.subtract_usage(file_list_memory);
            return Ok(Vec::new());
        }

        // Step 3: Process groups in batches if memory usage is high
        let mut duplicate_sets = Vec::new();
        
        if self.memory_monitor.should_cleanup() || potential_duplicate_groups.len() > 100 {
            println!("Processing {} groups in batches for memory efficiency", potential_duplicate_groups.len());
            
            // Process groups in smaller batches to manage memory
            let batch_size = if self.memory_monitor.is_memory_critical() { 10 } else { 50 };
            
            for batch_start in (0..potential_duplicate_groups.len()).step_by(batch_size) {
                let batch_end = (batch_start + batch_size).min(potential_duplicate_groups.len());
                let batch_groups = potential_duplicate_groups[batch_start..batch_end].to_vec();
                
                println!("Processing batch {}-{} of {} groups using {} threads...", 
                         batch_start + 1, batch_end, potential_duplicate_groups.len(), self.thread_count);
                
                // Wait if memory is critically high
                while self.memory_monitor.is_memory_critical() {
                    eprintln!("Memory usage critical, waiting before processing next batch...");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                
                let batch_duplicates = self.duplicate_matcher.find_duplicate_sets(batch_groups).await?;
                duplicate_sets.extend(batch_duplicates);
                
                // Trigger cleanup after each batch
                if self.memory_monitor.should_cleanup() {
                    self.memory_monitor.mark_cleanup();
                    // Force a small delay to allow garbage collection
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        } else {
            // Process all groups at once if memory usage is acceptable
            println!("Computing hashes for {} groups with potential duplicates using {} threads...", 
                     potential_duplicate_groups.len(), self.thread_count);
            duplicate_sets = self.duplicate_matcher.find_duplicate_sets(potential_duplicate_groups).await?;
        }
        
        println!("Found {} duplicate sets", duplicate_sets.len());
        
        // Clean up memory tracking
        self.memory_monitor.subtract_usage(file_list_memory);
        
        Ok(duplicate_sets)
    }

    /// Set the hash algorithm to use
    pub async fn set_hash_algorithm(&mut self, algorithm: HashAlgorithm) {
        self.hash_algorithm = algorithm;
        self.duplicate_matcher.set_algorithm(algorithm).await;
    }

    /// Set the number of threads for parallel processing
    pub fn set_parallelism(&mut self, thread_count: usize) {
        self.thread_count = thread_count;
        self.duplicate_matcher.set_parallelism(thread_count);
    }

    /// Get the current parallelism setting
    pub fn get_parallelism(&self) -> usize {
        self.thread_count
    }

    /// Get size grouping statistics from the last analysis
    pub fn get_size_grouping_stats(&self) -> SizeGroupingStats {
        self.size_grouper.get_statistics()
    }

    /// Get hash computation cache statistics
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        self.duplicate_matcher.get_cache_stats().await
    }

    /// Clear all caches
    pub async fn clear_caches(&mut self) {
        self.size_grouper.clear();
        self.duplicate_matcher.clear_cache().await;
        self.memory_monitor.reset();
    }

    /// Get current memory usage statistics
    pub fn get_memory_stats(&self) -> (usize, usize, f64) {
        (
            self.memory_monitor.current_usage(),
            self.memory_monitor.max_memory(),
            self.memory_monitor.usage_percentage(),
        )
    }

    /// Set memory limit
    pub fn set_memory_limit(&mut self, max_memory: usize) {
        self.memory_monitor = MemoryMonitor::new(max_memory);
    }
}

impl Default for DuplicateDetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::PathBuf;
    use std::time::UNIX_EPOCH;

    // Property-based test generators
    prop_compose! {
        fn arb_file_metadata()(
            path_str in "[a-zA-Z0-9_/.-]{1,50}",
            size in 0u64..1_000_000_000,
        ) -> FileMetadata {
            FileMetadata::new(
                PathBuf::from(path_str),
                size,
                UNIX_EPOCH,
                true,
            )
        }
    }

    prop_compose! {
        fn arb_file_list()(
            files in prop::collection::vec(arb_file_metadata(), 1..100)
        ) -> Vec<FileMetadata> {
            files
        }
    }

    fn create_test_file(path: &str, size: u64) -> FileMetadata {
        FileMetadata::new(
            PathBuf::from(path),
            size,
            UNIX_EPOCH,
            true,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: duplicate-file-analyzer, Property 3: Efficient Algorithm Ordering**
        /// **Validates: Requirements 2.1, 2.2, 2.5**
        /// For any set of files being analyzed, size comparison should occur before hash computation, 
        /// and hash computation should only occur for files with matching sizes
        #[test]
        fn test_efficient_algorithm_ordering(files in arb_file_list()) {
            let mut grouper = SizeGrouper::new();
            
            // Group files by size
            grouper.group_files(files.clone());
            let stats = grouper.get_statistics();
            
            // Property: All input files should be accounted for
            prop_assert_eq!(stats.total_files, files.len());
            
            // Property: Sum of unique files and potential duplicates should equal total files
            prop_assert_eq!(stats.unique_files + stats.potential_duplicates, stats.total_files);
            
            // Property: Files with unique sizes should not require hash computation
            let unique_files = grouper.get_unique_files();
            prop_assert_eq!(unique_files.len(), stats.unique_files);
            
            // Property: Only files in groups with size > 1 should need hash computation
            let potential_duplicates = grouper.get_potential_duplicates();
            let total_potential_files: usize = potential_duplicates.iter().map(|group| group.len()).sum();
            prop_assert_eq!(total_potential_files, stats.potential_duplicates);
            
            // Property: Each size group should contain files with identical sizes
            for group in potential_duplicates {
                if !group.is_empty() {
                    let expected_size = group[0].size;
                    for file in group {
                        prop_assert_eq!(file.size, expected_size);
                    }
                }
            }
            
            // Property: All unique files should have different sizes from each other
            let unique_files = grouper.get_unique_files();
            let mut unique_sizes = std::collections::HashSet::new();
            for file in unique_files {
                prop_assert!(unique_sizes.insert(file.size), "Unique files should have different sizes");
            }
            
            // Property: Efficiency gain should be between 0 and 100 percent
            let efficiency = stats.efficiency_gain();
            prop_assert!(efficiency >= 0.0 && efficiency <= 100.0);
            
            // Property: If all files have unique sizes, efficiency should be 100%
            if stats.duplicate_groups == 0 {
                prop_assert_eq!(efficiency, 100.0);
            }
            
            // Property: If no files have unique sizes, efficiency should be 0%
            if stats.unique_files == 0 && stats.total_files > 0 {
                prop_assert_eq!(efficiency, 0.0);
            }
        }

        /// Test that size grouping is deterministic and consistent
        #[test]
        fn test_size_grouping_deterministic(files in arb_file_list()) {
            let mut grouper1 = SizeGrouper::new();
            let mut grouper2 = SizeGrouper::new();
            
            // Group the same files twice
            grouper1.group_files(files.clone());
            grouper2.group_files(files);
            
            let stats1 = grouper1.get_statistics();
            let stats2 = grouper2.get_statistics();
            
            // Property: Results should be identical
            prop_assert_eq!(stats1.total_files, stats2.total_files);
            prop_assert_eq!(stats1.unique_files, stats2.unique_files);
            prop_assert_eq!(stats1.potential_duplicates, stats2.potential_duplicates);
            prop_assert_eq!(stats1.size_groups, stats2.size_groups);
            prop_assert_eq!(stats1.duplicate_groups, stats2.duplicate_groups);
            
            // Property: Potential duplicates should be the same
            let potential1 = grouper1.get_potential_duplicates();
            let potential2 = grouper2.get_potential_duplicates();
            prop_assert_eq!(potential1.len(), potential2.len());
            
            // Property: Unique files should be the same
            let unique1 = grouper1.get_unique_files();
            let unique2 = grouper2.get_unique_files();
            prop_assert_eq!(unique1.len(), unique2.len());
        }

        /// Test edge cases for size grouping
        #[test]
        fn test_size_grouping_edge_cases(
            files in prop::collection::vec(arb_file_metadata(), 0..10)
        ) {
            let mut grouper = SizeGrouper::new();
            grouper.group_files(files.clone());
            let stats = grouper.get_statistics();
            
            // Property: Statistics should be consistent with input
            prop_assert_eq!(stats.total_files, files.len());
            
            // Property: If no files, all stats should be zero
            if files.is_empty() {
                prop_assert_eq!(stats.unique_files, 0);
                prop_assert_eq!(stats.potential_duplicates, 0);
                prop_assert_eq!(stats.size_groups, 0);
                prop_assert_eq!(stats.duplicate_groups, 0);
                prop_assert_eq!(stats.efficiency_gain(), 0.0);
                prop_assert_eq!(stats.potential_duplicate_percentage(), 0.0);
            }
            
            // Property: Number of size groups should not exceed number of files
            prop_assert!(stats.size_groups <= stats.total_files);
            
            // Property: Number of duplicate groups should not exceed size groups
            prop_assert!(stats.duplicate_groups <= stats.size_groups);
        }

        /// **Feature: duplicate-file-analyzer, Property 4: Correct Duplicate Grouping**
        /// **Validates: Requirements 2.4**
        /// For any files with identical content hashes, they should be grouped together as a duplicate set
        #[test]
        fn test_correct_duplicate_grouping(
            // Generate files with some having identical content
            file_contents in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..1000), // Generate different file contents
                1..10
            )
        ) {
            tokio_test::block_on(async {
                use tempfile::TempDir;
                use std::fs;
                
                let temp_dir = TempDir::new().unwrap();
                let mut files = Vec::new();
                let mut expected_duplicates = std::collections::HashMap::new();
                
                // Create test files with the generated content
                for (i, content) in file_contents.iter().enumerate() {
                    let file_path = temp_dir.path().join(format!("file_{}.txt", i));
                    fs::write(&file_path, content).unwrap();
                    
                    let metadata = FileMetadata::new(
                        file_path,
                        content.len() as u64,
                        UNIX_EPOCH,
                        true,
                    );
                    files.push(metadata);
                    
                    // Track expected duplicates by content
                    expected_duplicates.entry(content.clone()).or_insert_with(Vec::new).push(i);
                }
                
                // Run duplicate detection
                let mut engine = DuplicateDetectionEngine::new();
                let duplicate_sets = engine.find_duplicates(files.clone()).await.unwrap();
                
                // Property: Only files with identical content should be grouped together
                for duplicate_set in &duplicate_sets {
                    prop_assert!(duplicate_set.files.len() > 1, "Duplicate sets should have more than 1 file");
                    
                    // All files in a duplicate set should have the same hash
                    let expected_hash = &duplicate_set.hash;
                    for file in &duplicate_set.files {
                        prop_assert_eq!(file.get_hash(), Some(expected_hash.as_str()));
                    }
                    
                    // All files in a duplicate set should have the same size
                    let expected_size = duplicate_set.total_size;
                    for file in &duplicate_set.files {
                        prop_assert_eq!(file.size, expected_size);
                    }
                    
                    // Potential savings should be calculated correctly
                    let expected_savings = expected_size * (duplicate_set.files.len() as u64 - 1);
                    prop_assert_eq!(duplicate_set.potential_savings, expected_savings);
                }
                
                // Property: Files with different content should not be in the same duplicate set
                for duplicate_set in &duplicate_sets {
                    // Read the actual content of all files in this set
                    let mut contents = Vec::new();
                    for file in &duplicate_set.files {
                        let content = fs::read(&file.path).unwrap();
                        contents.push(content);
                    }
                    
                    // All contents should be identical
                    if !contents.is_empty() {
                        let first_content = &contents[0];
                        for content in &contents[1..] {
                            prop_assert_eq!(content, first_content, 
                                "All files in a duplicate set should have identical content");
                        }
                    }
                }
                
                // Property: Each file should appear in at most one duplicate set
                let mut all_files_in_sets = std::collections::HashSet::new();
                for duplicate_set in &duplicate_sets {
                    for file in &duplicate_set.files {
                        prop_assert!(all_files_in_sets.insert(&file.path), 
                            "Each file should appear in at most one duplicate set");
                    }
                }
                
                // Property: If we have files with identical content, they should be detected as duplicates
                let content_groups: std::collections::HashMap<Vec<u8>, Vec<usize>> = 
                    file_contents.iter().enumerate()
                        .fold(std::collections::HashMap::new(), |mut acc, (i, content)| {
                            acc.entry(content.clone()).or_insert_with(Vec::new).push(i);
                            acc
                        });
                
                let expected_duplicate_groups: Vec<_> = content_groups.values()
                    .filter(|group| group.len() > 1)
                    .collect();
                
                // The number of duplicate sets should match the number of content groups with duplicates
                prop_assert_eq!(duplicate_sets.len(), expected_duplicate_groups.len(),
                    "Number of duplicate sets should match number of content groups with duplicates");
                
                Ok(())
            })?;
        }
    }

    #[test]
    fn test_size_grouper_basic_functionality() {
        let mut grouper = SizeGrouper::new();
        
        let files = vec![
            create_test_file("file1.txt", 100),
            create_test_file("file2.txt", 200),
            create_test_file("file3.txt", 100), // Same size as file1
            create_test_file("file4.txt", 300),
            create_test_file("file5.txt", 200), // Same size as file2
        ];

        let groups = grouper.group_files(files);
        
        // Should have 3 size groups (100, 200, 300)
        assert_eq!(groups.len(), 3);
        assert!(groups.contains_key(&100));
        assert!(groups.contains_key(&200));
        assert!(groups.contains_key(&300));
        
        // Size 100 should have 2 files
        assert_eq!(groups[&100].len(), 2);
        // Size 200 should have 2 files
        assert_eq!(groups[&200].len(), 2);
        // Size 300 should have 1 file
        assert_eq!(groups[&300].len(), 1);
    }

    #[test]
    fn test_size_grouper_potential_duplicates() {
        let mut grouper = SizeGrouper::new();
        
        let files = vec![
            create_test_file("file1.txt", 100),
            create_test_file("file2.txt", 200),
            create_test_file("file3.txt", 100), // Potential duplicate
            create_test_file("file4.txt", 300), // Unique size
        ];

        grouper.group_files(files);
        
        let potential_duplicates = grouper.get_potential_duplicates();
        let unique_files = grouper.get_unique_files();
        
        // Should have 1 group with potential duplicates (size 100)
        assert_eq!(potential_duplicates.len(), 1);
        assert_eq!(potential_duplicates[0].len(), 2);
        
        // Should have 2 unique files (size 200 and 300)
        assert_eq!(unique_files.len(), 2);
    }

    #[test]
    fn test_size_grouper_statistics() {
        let mut grouper = SizeGrouper::new();
        
        let files = vec![
            create_test_file("file1.txt", 100),
            create_test_file("file2.txt", 100), // Duplicate size
            create_test_file("file3.txt", 200), // Unique size
            create_test_file("file4.txt", 300), // Unique size
            create_test_file("file5.txt", 100), // Another duplicate size
        ];

        grouper.group_files(files);
        let stats = grouper.get_statistics();
        
        assert_eq!(stats.total_files, 5);
        assert_eq!(stats.unique_files, 2); // files with size 200 and 300
        assert_eq!(stats.potential_duplicates, 3); // files with size 100
        assert_eq!(stats.size_groups, 3); // groups for sizes 100, 200, 300
        assert_eq!(stats.duplicate_groups, 1); // only size 100 has duplicates
        
        // Check percentage calculations
        assert_eq!(stats.potential_duplicate_percentage(), 60.0); // 3/5 * 100
        assert_eq!(stats.efficiency_gain(), 40.0); // 2/5 * 100
    }

    #[test]
    fn test_size_grouper_empty_input() {
        let mut grouper = SizeGrouper::new();
        
        let files = vec![];
        grouper.group_files(files);
        
        let stats = grouper.get_statistics();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.unique_files, 0);
        assert_eq!(stats.potential_duplicates, 0);
        assert_eq!(stats.size_groups, 0);
        assert_eq!(stats.duplicate_groups, 0);
        assert_eq!(stats.potential_duplicate_percentage(), 0.0);
        assert_eq!(stats.efficiency_gain(), 0.0);
    }

    #[test]
    fn test_size_grouper_all_unique() {
        let mut grouper = SizeGrouper::new();
        
        let files = vec![
            create_test_file("file1.txt", 100),
            create_test_file("file2.txt", 200),
            create_test_file("file3.txt", 300),
        ];

        grouper.group_files(files);
        let stats = grouper.get_statistics();
        
        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.unique_files, 3);
        assert_eq!(stats.potential_duplicates, 0);
        assert_eq!(stats.size_groups, 3);
        assert_eq!(stats.duplicate_groups, 0);
        assert_eq!(stats.potential_duplicate_percentage(), 0.0);
        assert_eq!(stats.efficiency_gain(), 100.0);
    }

    #[tokio::test]
    async fn test_duplicate_detection_engine_with_size_grouper() {
        let mut engine = DuplicateDetectionEngine::new();
        
        let files = vec![
            create_test_file("file1.txt", 100),
            create_test_file("file2.txt", 200),
            create_test_file("file3.txt", 100), // Same size as file1
        ];

        // This should complete without error and use size grouping
        let result = engine.find_duplicates(files).await;
        assert!(result.is_ok());
        
        // Check that size grouping statistics are available
        let stats = engine.get_size_grouping_stats();
        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.duplicate_groups, 1);
    }

    #[tokio::test]
    async fn test_duplicate_matcher_basic_functionality() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let mut matcher = DuplicateMatcher::new(HashAlgorithm::Sha256);
        
        // Create test files with identical content
        let mut file1 = NamedTempFile::new().unwrap();
        let mut file2 = NamedTempFile::new().unwrap();
        let mut file3 = NamedTempFile::new().unwrap();
        
        let content = b"Hello, World!";
        file1.write_all(content).unwrap();
        file2.write_all(content).unwrap();
        file3.write_all(b"Different content").unwrap();
        
        file1.flush().unwrap();
        file2.flush().unwrap();
        file3.flush().unwrap();
        
        // Create file metadata
        let metadata1 = FileMetadata::new(file1.path().to_path_buf(), content.len() as u64, UNIX_EPOCH, true);
        let metadata2 = FileMetadata::new(file2.path().to_path_buf(), content.len() as u64, UNIX_EPOCH, true);
        let metadata3 = FileMetadata::new(file3.path().to_path_buf(), 17, UNIX_EPOCH, true);
        
        // Group files by size (file1 and file2 have same size)
        let size_group1 = vec![metadata1, metadata2];
        let size_group2 = vec![metadata3];
        let size_groups = vec![&size_group1, &size_group2];
        
        // Find duplicates
        let duplicate_sets = matcher.find_duplicate_sets(size_groups).await.unwrap();
        
        // Should find one duplicate set (file1 and file2)
        assert_eq!(duplicate_sets.len(), 1);
        assert_eq!(duplicate_sets[0].files.len(), 2);
        assert!(duplicate_sets[0].has_duplicates());
        assert_eq!(duplicate_sets[0].total_size, content.len() as u64);
        assert_eq!(duplicate_sets[0].potential_savings, content.len() as u64);
    }

    #[tokio::test]
    async fn test_duplicate_matcher_no_duplicates() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let mut matcher = DuplicateMatcher::new(HashAlgorithm::Sha256);
        
        // Create test files with different content but same size
        let mut file1 = NamedTempFile::new().unwrap();
        let mut file2 = NamedTempFile::new().unwrap();
        
        file1.write_all(b"Hello, World!").unwrap();
        file2.write_all(b"Goodbye, All!").unwrap(); // Same length, different content
        
        file1.flush().unwrap();
        file2.flush().unwrap();
        
        // Create file metadata
        let metadata1 = FileMetadata::new(file1.path().to_path_buf(), 13, UNIX_EPOCH, true);
        let metadata2 = FileMetadata::new(file2.path().to_path_buf(), 13, UNIX_EPOCH, true);
        
        let size_group = vec![metadata1, metadata2];
        let size_groups = vec![&size_group];
        
        // Find duplicates
        let duplicate_sets = matcher.find_duplicate_sets(size_groups).await.unwrap();
        
        // Should find no duplicate sets (different content)
        assert_eq!(duplicate_sets.len(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_matcher_inaccessible_files() {
        let mut matcher = DuplicateMatcher::new(HashAlgorithm::Sha256);
        
        // Create file metadata for inaccessible files
        let metadata1 = FileMetadata::new("/nonexistent/file1.txt".into(), 100, UNIX_EPOCH, false);
        let metadata2 = FileMetadata::new("/nonexistent/file2.txt".into(), 100, UNIX_EPOCH, false);
        
        let size_group = vec![metadata1, metadata2];
        let size_groups = vec![&size_group];
        
        // Find duplicates - should handle inaccessible files gracefully
        let duplicate_sets = matcher.find_duplicate_sets(size_groups).await.unwrap();
        
        // Should find no duplicate sets (files are inaccessible)
        assert_eq!(duplicate_sets.len(), 0);
    }

    #[tokio::test]
    async fn test_complete_duplicate_detection_workflow() {
        use tempfile::TempDir;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        
        // Create test files
        let file1_path = temp_dir.path().join("file1.txt");
        let file2_path = temp_dir.path().join("file2.txt");
        let file3_path = temp_dir.path().join("file3.txt");
        let file4_path = temp_dir.path().join("file4.txt");
        
        let content1 = b"Hello, World!";
        let content2 = b"Hello, World!"; // Duplicate of content1
        let content3 = b"Different content";
        let content4 = b"Another different content";
        
        fs::write(&file1_path, content1).unwrap();
        fs::write(&file2_path, content2).unwrap();
        fs::write(&file3_path, content3).unwrap();
        fs::write(&file4_path, content4).unwrap();
        
        // Create file metadata
        let files = vec![
            FileMetadata::new(file1_path, content1.len() as u64, UNIX_EPOCH, true),
            FileMetadata::new(file2_path, content2.len() as u64, UNIX_EPOCH, true),
            FileMetadata::new(file3_path, content3.len() as u64, UNIX_EPOCH, true),
            FileMetadata::new(file4_path, content4.len() as u64, UNIX_EPOCH, true),
        ];
        
        let mut engine = DuplicateDetectionEngine::new();
        let duplicate_sets = engine.find_duplicates(files).await.unwrap();
        
        // Should find one duplicate set (file1 and file2)
        assert_eq!(duplicate_sets.len(), 1);
        assert_eq!(duplicate_sets[0].files.len(), 2);
        assert!(duplicate_sets[0].has_duplicates());
        
        // Check that both files have the same hash
        let hash1 = duplicate_sets[0].files[0].get_hash().unwrap();
        let hash2 = duplicate_sets[0].files[1].get_hash().unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(duplicate_sets[0].hash, hash1);
    }
}
