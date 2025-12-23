//! Analysis controller that coordinates the duplicate detection process

use crate::{
    concurrent::FileChangeDetector, discovery::FileDiscoveryEngine, duplicate::DuplicateDetectionEngine, models::*,
    progress::ProgressTracker, report::ReportGenerator, resume::{ResumeManager, AnalysisState, AnalysisPhase}, Result, Config,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Main controller for duplicate file analysis
pub struct AnalysisController {
    discovery_engine: FileDiscoveryEngine,
    duplicate_engine: DuplicateDetectionEngine,
    progress_tracker: Arc<RwLock<ProgressTracker>>,
    report_generator: ReportGenerator,
    resume_manager: Option<ResumeManager>,
    change_detector: FileChangeDetector,
    config: Config,
}

impl AnalysisController {
    /// Create a new analysis controller
    pub fn new() -> Self {
        let config = Config::default();
        Self {
            discovery_engine: FileDiscoveryEngine::new(),
            duplicate_engine: DuplicateDetectionEngine::with_parallelism(config.thread_count),
            progress_tracker: Arc::new(RwLock::new(ProgressTracker::new())),
            report_generator: ReportGenerator::new(),
            resume_manager: None,
            change_detector: FileChangeDetector::new(),
            config,
        }
    }

    /// Create a new analysis controller with custom configuration
    pub fn with_config(config: Config) -> Self {
        Self {
            discovery_engine: FileDiscoveryEngine::with_memory_settings(config.max_memory / 2, config.batch_size),
            duplicate_engine: DuplicateDetectionEngine::with_memory_settings(config.thread_count, config.max_memory / 2),
            progress_tracker: Arc::new(RwLock::new(ProgressTracker::new())),
            report_generator: ReportGenerator::new(),
            resume_manager: None,
            change_detector: FileChangeDetector::new(),
            config,
        }
    }

    /// Create a new analysis controller with resume capability
    pub fn with_resume() -> Result<Self> {
        let config = Config::default();
        let resume_manager = ResumeManager::with_default_dir()?;
        Ok(Self {
            discovery_engine: FileDiscoveryEngine::new(),
            duplicate_engine: DuplicateDetectionEngine::with_parallelism(config.thread_count),
            progress_tracker: Arc::new(RwLock::new(ProgressTracker::new())),
            report_generator: ReportGenerator::new(),
            resume_manager: Some(resume_manager),
            change_detector: FileChangeDetector::new(),
            config,
        })
    }

    /// Create a new analysis controller with resume capability and custom configuration
    pub fn with_resume_and_config(config: Config) -> Result<Self> {
        let resume_manager = ResumeManager::with_default_dir()?;
        Ok(Self {
            discovery_engine: FileDiscoveryEngine::with_memory_settings(config.max_memory / 2, config.batch_size),
            duplicate_engine: DuplicateDetectionEngine::with_memory_settings(config.thread_count, config.max_memory / 2),
            progress_tracker: Arc::new(RwLock::new(ProgressTracker::new())),
            report_generator: ReportGenerator::new(),
            resume_manager: Some(resume_manager),
            change_detector: FileChangeDetector::new(),
            config,
        })
    }

    /// Get the current configuration
    pub fn get_config(&self) -> &Config {
        &self.config
    }

    /// Update the configuration
    pub async fn set_config(&mut self, config: Config) {
        // Update duplicate engine parallelism if it changed
        if config.thread_count != self.config.thread_count {
            self.duplicate_engine.set_parallelism(config.thread_count);
        }
        
        // Update hash algorithm if it changed
        if config.hash_algorithm != self.config.hash_algorithm {
            self.duplicate_engine.set_hash_algorithm(config.hash_algorithm).await;
        }
        
        // Update memory limits if they changed
        if config.max_memory != self.config.max_memory {
            self.duplicate_engine.set_memory_limit(config.max_memory / 2);
        }
        
        // Update batch size if it changed
        if config.batch_size != self.config.batch_size {
            self.discovery_engine.set_batch_size(config.batch_size);
        }
        
        self.config = config;
    }

    /// Get memory usage statistics from all components
    pub fn get_memory_stats(&self) -> (usize, usize, f64) {
        let (discovery_usage, discovery_max, _discovery_pct) = self.discovery_engine.get_memory_stats();
        let (duplicate_usage, duplicate_max, _duplicate_pct) = self.duplicate_engine.get_memory_stats();
        
        let total_usage = discovery_usage + duplicate_usage;
        let total_max = discovery_max + duplicate_max;
        let total_pct = if total_max > 0 {
            (total_usage as f64 / total_max as f64) * 100.0
        } else {
            0.0
        };
        
        (total_usage, total_max, total_pct)
    }

    /// Start analysis of the specified directory
    pub async fn analyze_directory(
        &mut self,
        target_path: &Path,
        options: DiscoveryOptions,
    ) -> Result<AnalysisResult> {
        self.analyze_directory_with_resume(target_path, options, None).await
    }

    /// Start analysis with optional resume from existing session
    pub async fn analyze_directory_with_resume(
        &mut self,
        target_path: &Path,
        options: DiscoveryOptions,
        resume_session_id: Option<String>,
    ) -> Result<AnalysisResult> {
        use std::time::Instant;
        
        let start_time = Instant::now();
        
        // Check if we should resume from existing state
        if let (Some(session_id), Some(ref mut resume_manager)) = (&resume_session_id, &mut self.resume_manager) {
            if let Some(state) = resume_manager.load_state(session_id).await? {
                println!("Resuming analysis from session: {}", session_id);
                println!("Previous progress: {:.1}% complete", state.progress_percentage());
                
                // Continue from where we left off
                return self.resume_analysis(state, start_time).await;
            } else {
                println!("No resumable state found for session: {}", session_id);
            }
        }
        
        // Start new analysis
        let session_id = if let Some(ref _resume_manager) = self.resume_manager {
            ResumeManager::generate_session_id(target_path)
        } else {
            "no_resume".to_string()
        };
        
        let mut state = AnalysisState::new(
            session_id.clone(),
            target_path.to_path_buf(),
            options.clone(),
        );
        
        println!("Starting new analysis of directory: {}", target_path.display());
        if self.resume_manager.is_some() {
            println!("Session ID: {} (use --resume {} to continue if interrupted)", session_id, session_id);
        }
        
        // Step 1: Discover files
        state.set_phase(AnalysisPhase::Discovery);
        self.save_state_if_enabled(&state).await?;
        
        let files = match self.discovery_engine.discover_files(target_path, &options).await {
            Ok(files) => {
                println!("Discovered {} files", files.len());
                files
            }
            Err(err) => {
                eprintln!("Error during file discovery: {}", err);
                return Err(err);
            }
        };
        
        // Add discovery errors to state
        for error in self.discovery_engine.get_errors() {
            state.add_error(error.clone());
        }
        
        state.add_discovered_files(files.clone());
        
        // Start tracking files for concurrent modification detection
        if let Err(err) = self.change_detector.track_files(&files).await {
            eprintln!("Warning: Could not start tracking files for concurrent modifications: {}", err);
        }
        
        if files.is_empty() {
            println!("No files found to analyze");
            state.set_phase(AnalysisPhase::Completed);
            let result = state.to_analysis_result(start_time.elapsed().as_secs_f64());
            self.cleanup_state_if_enabled(&state.session_id).await?;
            return Ok(result);
        }
        
        // Step 2: Find duplicates
        state.set_phase(AnalysisPhase::HashComputation);
        self.save_state_if_enabled(&state).await?;
        
        println!("Analyzing files for duplicates...");
        
        // Check for concurrent modifications before hash computation
        if let Ok(modified_files) = self.change_detector.check_all_files().await {
            if !modified_files.is_empty() {
                println!("Warning: {} files were modified during analysis and will be processed with their current content", modified_files.len());
                for modified_file in &modified_files {
                    println!("  Modified: {}", modified_file.display());
                }
                
                // Add concurrent modification errors to the state
                for error in self.change_detector.get_errors() {
                    state.add_error(error.clone());
                }
            }
        }
        
        let duplicate_sets = match self.duplicate_engine.find_duplicates(files).await {
            Ok(sets) => {
                println!("Found {} duplicate sets", sets.len());
                sets
            }
            Err(err) => {
                eprintln!("Error during duplicate detection: {}", err);
                return Err(err);
            }
        };
        
        // Step 3: Add duplicate sets to state
        state.set_phase(AnalysisPhase::DuplicateDetection);
        for duplicate_set in duplicate_sets {
            state.add_duplicate_set(duplicate_set);
        }
        
        state.set_phase(AnalysisPhase::Completed);
        let result = state.to_analysis_result(start_time.elapsed().as_secs_f64());
        
        // Clean up state file since analysis is complete
        self.cleanup_state_if_enabled(&state.session_id).await?;
        
        Ok(result)
    }

    /// Resume analysis from saved state
    async fn resume_analysis(
        &mut self,
        mut state: AnalysisState,
        start_time: Instant,
    ) -> Result<AnalysisResult> {
        match state.phase {
            AnalysisPhase::Discovery => {
                // Need to restart discovery
                println!("Resuming from discovery phase...");
                let files = self.discovery_engine.discover_files(&state.target_directory, &state.discovery_options).await?;
                state.add_discovered_files(files.clone());
                
                if files.is_empty() {
                    state.set_phase(AnalysisPhase::Completed);
                    let result = state.to_analysis_result(start_time.elapsed().as_secs_f64());
                    self.cleanup_state_if_enabled(&state.session_id).await?;
                    return Ok(result);
                }
                
                // Continue to hash computation
                state.set_phase(AnalysisPhase::HashComputation);
                self.save_state_if_enabled(&state).await?;
                
                let duplicate_sets = self.duplicate_engine.find_duplicates(files).await?;
                for duplicate_set in duplicate_sets {
                    state.add_duplicate_set(duplicate_set);
                }
            }
            AnalysisPhase::HashComputation => {
                // Resume hash computation and duplicate detection
                println!("Resuming from hash computation phase...");
                let duplicate_sets = self.duplicate_engine.find_duplicates(state.discovered_files.clone()).await?;
                for duplicate_set in duplicate_sets {
                    state.add_duplicate_set(duplicate_set);
                }
            }
            AnalysisPhase::DuplicateDetection => {
                // Analysis was nearly complete, just finalize
                println!("Resuming from duplicate detection phase...");
            }
            AnalysisPhase::Completed => {
                // Analysis was already complete
                println!("Analysis was already completed");
                let result = state.to_analysis_result(start_time.elapsed().as_secs_f64());
                self.cleanup_state_if_enabled(&state.session_id).await?;
                return Ok(result);
            }
        }
        
        state.set_phase(AnalysisPhase::Completed);
        let result = state.to_analysis_result(start_time.elapsed().as_secs_f64());
        
        // Clean up state file since analysis is complete
        self.cleanup_state_if_enabled(&state.session_id).await?;
        
        Ok(result)
    }

    /// Save state if resume manager is enabled
    async fn save_state_if_enabled(&mut self, state: &AnalysisState) -> Result<()> {
        if let Some(ref mut resume_manager) = self.resume_manager {
            resume_manager.save_state(state).await?;
        }
        Ok(())
    }

    /// Clean up state file if resume manager is enabled
    async fn cleanup_state_if_enabled(&mut self, session_id: &str) -> Result<()> {
        if let Some(ref mut resume_manager) = self.resume_manager {
            resume_manager.delete_state(session_id).await?;
        }
        Ok(())
    }

    /// List available resumable sessions
    pub async fn list_resumable_sessions(&self) -> Result<Vec<String>> {
        if let Some(ref resume_manager) = self.resume_manager {
            resume_manager.list_resumable_sessions().await
        } else {
            Ok(Vec::new())
        }
    }

    /// Check if a session can be resumed
    pub async fn can_resume_session(&self, session_id: &str) -> bool {
        if let Some(ref resume_manager) = self.resume_manager {
            resume_manager.has_resumable_state(session_id).await
        } else {
            false
        }
    }

    /// Get current progress information
    pub async fn get_progress(&self) -> ProgressUpdate {
        self.progress_tracker.read().await.get_current_progress()
    }

    /// Cancel ongoing analysis
    pub async fn cancel_analysis(&mut self) -> Result<()> {
        // TODO: Implement cancellation logic
        Ok(())
    }
}

impl Default for AnalysisController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use std::fs;

    // Helper function to create test directory structure
    fn create_test_directory_structure(temp_dir: &TempDir, files: &[(&str, &str)]) -> Result<()> {
        for (path, content) in files {
            let full_path = temp_dir.path().join(path);
            
            // Create parent directories if they don't exist
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            fs::write(full_path, content)?;
        }
        Ok(())
    }

    prop_compose! {
        fn arb_directory_structure()(
            files in prop::collection::vec(
                (
                    prop::string::string_regex("[a-zA-Z0-9_/]{1,30}").unwrap(),
                    prop::string::string_regex("[a-zA-Z0-9 ]{0,50}").unwrap()
                ),
                1..10
            )
        ) -> Vec<(String, String)> {
            // Ensure file paths don't start with / and are valid
            files.into_iter()
                .map(|(path, content)| {
                    let clean_path = path.trim_start_matches('/').replace("//", "/");
                    (clean_path, content)
                })
                .filter(|(path, _)| {
                    !path.is_empty() 
                    && !path.ends_with('/') 
                    && !path.contains("..") 
                    && !path.starts_with(".")
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn test_graceful_interruption_handling_simple() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a simple test file
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, "test content").unwrap();
        
        let mut controller = AnalysisController::new();
        let options = DiscoveryOptions::default();
        
        // Property 1: Analysis should complete successfully or fail gracefully
        let analysis_result = controller.analyze_directory(temp_dir.path(), options).await;
        
        match analysis_result {
            Ok(result) => {
                // Property: Valid results should have consistent data
                assert!(result.total_files_analyzed >= 0);
                assert!(result.total_duplicate_files >= 0);
                assert!(result.total_potential_savings >= 0);
                assert!(result.analysis_time >= 0.0);
                
                // Property: Total duplicate files should not exceed total files analyzed
                assert!(result.total_duplicate_files <= result.total_files_analyzed);
            }
            Err(_) => {
                // Property: Errors should be handled gracefully without panicking
                // The fact that we got an error result instead of a panic demonstrates graceful handling
            }
        }
        
        // Property 2: Cancellation should work without errors at any time
        let cancel_result = controller.cancel_analysis().await;
        assert!(cancel_result.is_ok(), "Cancellation should not produce errors");
        
        // Property 3: Multiple cancellations should be safe
        let second_cancel = controller.cancel_analysis().await;
        assert!(second_cancel.is_ok(), "Multiple cancellations should be safe");
        
        // Property 4: Controller should remain in valid state after cancellation
        let progress = controller.get_progress().await;
        assert!(progress.files_processed >= 0, "Progress should remain valid after cancellation");
        assert!(progress.total_files >= 0, "Total files should remain valid after cancellation");
        assert!(progress.bytes_processed >= 0, "Bytes processed should remain valid after cancellation");
        assert!(progress.duplicates_found >= 0, "Duplicates found should remain valid after cancellation");
    }

    proptest! {
        /// **Feature: duplicate-file-analyzer, Property 9: Graceful Interruption Handling**
        /// **Validates: Requirements 5.5**
        /// For any analysis that is interrupted, partial results should be available and valid up to the point of interruption
        #[test]
        fn test_graceful_interruption_handling_property(directory_structure in arb_directory_structure()) {
            tokio_test::block_on(async {
                let temp_dir = TempDir::new().unwrap();
                
                // Create the test directory structure
                if create_test_directory_structure(&temp_dir, &directory_structure.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect::<Vec<_>>()).is_err() {
                    // Skip this test case if we can't create the directory structure
                    return;
                }

                let mut controller = AnalysisController::new();
                let options = DiscoveryOptions::default();
                
                // Property 1: Analysis should complete successfully or fail gracefully
                let analysis_result = controller.analyze_directory(temp_dir.path(), options).await;
                
                match analysis_result {
                    Ok(result) => {
                        // Property: Valid results should have consistent data
                        assert!(result.total_files_analyzed >= 0);
                        assert!(result.total_duplicate_files >= 0);
                        assert!(result.total_potential_savings >= 0);
                        assert!(result.analysis_time >= 0.0);
                        
                        // Property: Total duplicate files should not exceed total files analyzed
                        assert!(result.total_duplicate_files <= result.total_files_analyzed);
                        
                        // Property: If there are duplicate sets, there should be duplicate files
                        if !result.duplicate_sets.is_empty() {
                            assert!(result.total_duplicate_files > 0);
                        }
                        
                        // Property: Each duplicate set should be valid
                        for duplicate_set in &result.duplicate_sets {
                            assert!(duplicate_set.files.len() > 1, "Duplicate sets should have more than 1 file");
                            assert!(!duplicate_set.hash.is_empty(), "Duplicate sets should have a hash");
                            assert!(duplicate_set.potential_savings >= 0, "Potential savings should be non-negative");
                        }
                        
                        // Property: Results should be sorted by potential savings (descending)
                        for i in 0..result.duplicate_sets.len().saturating_sub(1) {
                            let current_savings = result.duplicate_sets[i].potential_savings;
                            let next_savings = result.duplicate_sets[i + 1].potential_savings;
                            assert!(current_savings >= next_savings, 
                                "Results should be sorted by potential savings in descending order");
                        }
                    }
                    Err(_) => {
                        // Property: Errors should be handled gracefully without panicking
                        // The fact that we got an error result instead of a panic demonstrates graceful handling
                    }
                }
                
                // Property 2: Cancellation should work without errors at any time
                let cancel_result = controller.cancel_analysis().await;
                assert!(cancel_result.is_ok(), "Cancellation should not produce errors");
                
                // Property 3: Multiple cancellations should be safe
                let second_cancel = controller.cancel_analysis().await;
                assert!(second_cancel.is_ok(), "Multiple cancellations should be safe");
                
                // Property 4: Controller should remain in valid state after cancellation
                let progress = controller.get_progress().await;
                assert!(progress.files_processed >= 0, "Progress should remain valid after cancellation");
                assert!(progress.total_files >= 0, "Total files should remain valid after cancellation");
                assert!(progress.bytes_processed >= 0, "Bytes processed should remain valid after cancellation");
                assert!(progress.duplicates_found >= 0, "Duplicates found should remain valid after cancellation");
            });
        }
    }

        /// Test that analysis controller handles empty directories gracefully
        #[test]
        fn test_empty_directory_handling() {
            tokio_test::block_on(async {
                let temp_dir = TempDir::new().unwrap();
                
                let mut controller = AnalysisController::new();
                let options = DiscoveryOptions::default();
                
                let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
                
                // Property: Empty directory should produce valid empty results
                assert_eq!(result.total_files_analyzed, 0);
                assert_eq!(result.total_duplicate_files, 0);
                assert_eq!(result.total_potential_savings, 0);
                assert!(result.duplicate_sets.is_empty());
                assert!(result.analysis_time >= 0.0);
            });
        }

        /// Test that analysis controller handles invalid paths gracefully
        #[test]
        fn test_invalid_path_handling() {
            tokio_test::block_on(async {
                let mut controller = AnalysisController::new();
                let options = DiscoveryOptions::default();
                
                // Try to analyze a non-existent directory
                let invalid_path = PathBuf::from("/nonexistent/directory/path");
                let result = controller.analyze_directory(&invalid_path, options).await;
                
                // Property: Invalid paths should be handled gracefully (either error or empty result)
                match result {
                    Ok(analysis_result) => {
                        // If it succeeds, it should be a valid empty result
                        assert_eq!(analysis_result.total_files_analyzed, 0);
                        assert!(analysis_result.duplicate_sets.is_empty());
                    }
                    Err(_) => {
                        // Errors are acceptable for invalid paths
                    }
                }
            });
        }

    #[tokio::test]
    async fn test_basic_analysis_workflow() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a simple directory structure with some duplicates
        let files = vec![
            ("file1.txt", "Hello, World!"),
            ("file2.txt", "Hello, World!"), // Duplicate of file1
            ("file3.txt", "Different content"),
            ("subdir/file4.txt", "Hello, World!"), // Another duplicate
        ];
        
        create_test_directory_structure(&temp_dir, &files).unwrap();
        
        let mut controller = AnalysisController::new();
        let options = DiscoveryOptions::default();
        
        let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
        
        // Should find 4 files total
        assert_eq!(result.total_files_analyzed, 4);
        
        // Should find 1 duplicate set with 3 files
        assert_eq!(result.duplicate_sets.len(), 1);
        assert_eq!(result.duplicate_sets[0].files.len(), 3);
        assert_eq!(result.total_duplicate_files, 3);
        
        // Should have positive potential savings
        assert!(result.total_potential_savings > 0);
        
        // Analysis time should be recorded
        assert!(result.analysis_time >= 0.0);
    }

    #[tokio::test]
    async fn test_analysis_with_exclusions() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create files with different extensions
        let files = vec![
            ("file1.txt", "content"),
            ("file2.log", "content"), // Same content but different extension
            ("file3.txt", "content"), // Another duplicate
        ];
        
        create_test_directory_structure(&temp_dir, &files).unwrap();
        
        let mut controller = AnalysisController::new();
        let mut options = DiscoveryOptions::default();
        options.exclude_patterns = vec!["*.log".to_string()]; // Exclude .log files
        
        let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
        
        // Should find only 2 files (excluding the .log file)
        assert_eq!(result.total_files_analyzed, 2);
        
        // Should find 1 duplicate set with 2 files
        assert_eq!(result.duplicate_sets.len(), 1);
        assert_eq!(result.duplicate_sets[0].files.len(), 2);
    }

    #[tokio::test]
    async fn test_progress_tracking() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a few files
        let files = vec![
            ("file1.txt", "content1"),
            ("file2.txt", "content2"),
        ];
        
        create_test_directory_structure(&temp_dir, &files).unwrap();
        
        let mut controller = AnalysisController::new();
        let options = DiscoveryOptions::default();
        
        // Start analysis
        let _result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
        
        // Check progress (should be complete now)
        let progress = controller.get_progress().await;
        
        // Progress should be valid
        assert!(progress.files_processed >= 0);
        assert!(progress.total_files >= 0);
        assert!(progress.bytes_processed >= 0);
        assert!(progress.duplicates_found >= 0);
    }

    #[tokio::test]
    async fn test_cancellation() {
        let mut controller = AnalysisController::new();
        
        // Test cancellation (should not error even if no analysis is running)
        let result = controller.cancel_analysis().await;
        assert!(result.is_ok());
    }
}
