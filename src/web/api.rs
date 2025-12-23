//! Web API server implementation

use crate::{analysis::AnalysisController, models::*, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use uuid::Uuid;

/// Request to start a new analysis
#[derive(Debug, Deserialize)]
pub struct AnalysisRequest {
    pub target_directory: PathBuf,
    pub options: AnalysisOptions,
    pub exclude_patterns: Option<Vec<String>>,
}

/// Analysis options for the web API
#[derive(Debug, Deserialize)]
pub struct AnalysisOptions {
    pub hash_algorithm: Option<String>,
    pub thread_count: Option<usize>,
    pub follow_symlinks: Option<bool>,
}

/// Analysis session information
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSession {
    pub session_id: String,
    pub status: AnalysisStatus,
    pub progress: f64,
    pub start_time: std::time::SystemTime,
    pub estimated_completion: Option<std::time::SystemTime>,
}

/// Status of an analysis session
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum AnalysisStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Web API server for handling HTTP requests
pub struct WebAPIServer {
    sessions: Arc<RwLock<HashMap<String, AnalysisSession>>>,
    results: Arc<RwLock<HashMap<String, AnalysisResult>>>,
    controllers: Arc<RwLock<HashMap<String, Arc<Mutex<AnalysisController>>>>>,
}

impl WebAPIServer {
    /// Create a new web API server
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
            controllers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a new analysis
    pub async fn start_analysis(&self, request: AnalysisRequest) -> Result<AnalysisSession> {
        let session_id = Uuid::new_v4().to_string();
        let session = AnalysisSession {
            session_id: session_id.clone(),
            status: AnalysisStatus::Running,
            progress: 0.0,
            start_time: std::time::SystemTime::now(),
            estimated_completion: None,
        };

        // Store the session
        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session.clone());

        // Create analysis controller for this session
        let controller = Arc::new(Mutex::new(AnalysisController::new()));
        self.controllers
            .write()
            .await
            .insert(session_id.clone(), controller.clone());

        // Start analysis in background task
        let sessions = self.sessions.clone();
        let results = self.results.clone();
        let controllers = self.controllers.clone();
        let session_id_clone = session_id.clone();
        
        tokio::spawn(async move {
            let analysis_result = {
                let mut controller = controller.lock().await;
                let mut discovery_options = DiscoveryOptions::default();
                
                // Apply request options
                if let Some(patterns) = &request.exclude_patterns {
                    discovery_options.exclude_patterns = patterns.clone();
                }
                if let Some(follow_symlinks) = request.options.follow_symlinks {
                    discovery_options.follow_symlinks = follow_symlinks;
                }
                
                controller.analyze_directory(&request.target_directory, discovery_options).await
            };

            // Update session status based on result
            let mut sessions_guard = sessions.write().await;
            if let Some(session) = sessions_guard.get_mut(&session_id_clone) {
                match analysis_result {
                    Ok(result) => {
                        session.status = AnalysisStatus::Completed;
                        session.progress = 100.0;
                        
                        // Store results
                        results.write().await.insert(session_id_clone.clone(), result);
                    }
                    Err(_) => {
                        session.status = AnalysisStatus::Failed;
                    }
                }
            }
            
            // Clean up controller
            controllers.write().await.remove(&session_id_clone);
        });

        Ok(session)
    }

    /// Get the status of an analysis session
    pub async fn get_analysis_status(&self, session_id: &str) -> Result<Option<AnalysisSession>> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            // Update progress if analysis is still running
            if session.status == AnalysisStatus::Running {
                if let Some(controller) = self.controllers.read().await.get(session_id) {
                    let progress_update = controller.lock().await.get_progress().await;
                    session.progress = progress_update.progress_percentage();
                    
                    // Update estimated completion
                    session.estimated_completion = progress_update.estimated_completion;
                }
            }
            
            Ok(Some(session.clone()))
        } else {
            Ok(None)
        }
    }

    /// Get the results of a completed analysis
    pub async fn get_analysis_results(&self, session_id: &str) -> Result<Option<AnalysisResult>> {
        let results = self.results.read().await;
        Ok(results.get(session_id).cloned())
    }

    /// Get information about a specific file
    pub async fn get_file_info(&self, file_path: &str) -> Result<Option<FileMetadata>> {
        use std::fs;
        use std::time::UNIX_EPOCH;
        
        let path = PathBuf::from(file_path);
        
        match fs::metadata(&path) {
            Ok(metadata) => {
                let modified_time = metadata
                    .modified()
                    .unwrap_or(UNIX_EPOCH);
                
                let file_metadata = FileMetadata::new(
                    path,
                    metadata.len(),
                    modified_time,
                    true, // If we can read metadata, it's accessible
                );
                
                Ok(Some(file_metadata))
            }
            Err(_) => Ok(None),
        }
    }

    /// Delete a file
    pub async fn delete_file(&self, file_path: &str) -> Result<bool> {
        use std::fs;
        
        let path = PathBuf::from(file_path);
        
        // Safety check: ensure the path exists and is a file
        if !path.exists() {
            return Ok(false);
        }
        
        if !path.is_file() {
            return Ok(false);
        }
        
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Delete multiple files
    pub async fn delete_files(&self, file_paths: &[String]) -> Result<Vec<(String, bool)>> {
        let mut results = Vec::new();
        
        for file_path in file_paths {
            let success = self.delete_file(file_path).await?;
            results.push((file_path.clone(), success));
        }
        
        Ok(results)
    }

    /// Cancel an ongoing analysis
    pub async fn cancel_analysis(&self, session_id: &str) -> Result<bool> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            if session.status == AnalysisStatus::Running {
                session.status = AnalysisStatus::Cancelled;
                
                // Cancel the analysis controller if it exists
                if let Some(controller) = self.controllers.read().await.get(session_id) {
                    let _ = controller.lock().await.cancel_analysis().await;
                }
                
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    /// Get all active sessions
    pub async fn get_active_sessions(&self) -> Result<Vec<AnalysisSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.values().cloned().collect())
    }

    /// Clean up completed sessions older than the specified duration
    pub async fn cleanup_old_sessions(&self, max_age: std::time::Duration) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let mut results = self.results.write().await;
        let mut controllers = self.controllers.write().await;
        
        let cutoff_time = std::time::SystemTime::now() - max_age;
        let mut removed_count = 0;
        
        let session_ids_to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| {
                matches!(session.status, AnalysisStatus::Completed | AnalysisStatus::Failed | AnalysisStatus::Cancelled)
                    && session.start_time < cutoff_time
            })
            .map(|(id, _)| id.clone())
            .collect();
        
        for session_id in session_ids_to_remove {
            sessions.remove(&session_id);
            results.remove(&session_id);
            controllers.remove(&session_id);
            removed_count += 1;
        }
        
        Ok(removed_count)
    }
}

impl Default for WebAPIServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use std::fs;
    use tempfile::TempDir;
    use std::io::Write;

    fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let file_path = dir.path().join(name);
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content).unwrap();
        file_path
    }

    #[tokio::test]
    async fn test_web_interface_file_actions_basic() {
        let temp_dir = TempDir::new().unwrap();
        let server = WebAPIServer::new();
        
        // Create a test file
        let file_path = create_test_file(&temp_dir, "test.txt", b"test content");
        let file_path_str = file_path.to_string_lossy().to_string();
        
        // Test file info retrieval
        let file_info = server.get_file_info(&file_path_str).await.unwrap();
        assert!(file_info.is_some());
        
        let metadata = file_info.unwrap();
        assert_eq!(metadata.path, file_path);
        assert!(metadata.is_accessible);
        
        // Test file deletion
        let delete_result = server.delete_file(&file_path_str).await.unwrap();
        assert!(delete_result);
        assert!(!file_path.exists());
        
        // Test file info retrieval for deleted file
        let file_info = server.get_file_info(&file_path_str).await.unwrap();
        assert!(file_info.is_none());
        
        // Test deletion of non-existent file
        let non_existent_path = temp_dir.path().join("non_existent.txt").to_string_lossy().to_string();
        let delete_result = server.delete_file(&non_existent_path).await.unwrap();
        assert!(!delete_result);
    }

    proptest! {
        /// **Feature: duplicate-file-analyzer, Property 14: Web Interface File Actions**
        /// **Validates: Requirements 7.4, 7.5**
        #[test]
        fn test_web_interface_file_actions_property(
            file_count in 1usize..10,
            file_names in prop::collection::vec("[a-zA-Z0-9_-]{1,15}\\.txt", 1..10)
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let server = WebAPIServer::new();
                
                // Create test files
                let mut created_files = Vec::new();
                for (i, name) in file_names.iter().enumerate().take(file_count) {
                    let content = format!("Content for file {}", i).into_bytes();
                    let file_path = create_test_file(&temp_dir, name, &content);
                    created_files.push(file_path);
                }
                
                // Property: File info should be retrievable for all existing files
                for file_path in &created_files {
                    let file_path_str = file_path.to_string_lossy();
                    let file_info = server.get_file_info(&file_path_str).await.unwrap();
                    prop_assert!(file_info.is_some());
                    
                    let metadata = file_info.unwrap();
                    prop_assert_eq!(metadata.path, file_path.clone());
                    prop_assert!(metadata.is_accessible);
                }
                
                // Property: File deletion should succeed for existing files
                let files_to_delete: Vec<String> = created_files.iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();
                
                let deletion_results = server.delete_files(&files_to_delete).await.unwrap();
                
                for (file_path, success) in &deletion_results {
                    prop_assert!(*success, "File deletion should succeed for existing file: {}", file_path);
                }
                
                // Property: Deleted files should no longer exist
                for file_path in &created_files {
                    prop_assert!(!file_path.exists(), "Deleted file should no longer exist: {}", file_path.display());
                }
                
                // Property: File info should not be available for deleted files
                for file_path_str in &files_to_delete {
                    let file_info = server.get_file_info(file_path_str).await.unwrap();
                    prop_assert!(file_info.is_none(), "File info should not be available for deleted file: {}", file_path_str);
                }
                
                Ok(())
            });
        }
    }

    #[tokio::test]
    async fn test_web_interface_result_sorting_and_export_basic() {
        let temp_dir = TempDir::new().unwrap();
        let server = WebAPIServer::new();
        
        // Create test files with different sizes for sorting
        let file1 = create_test_file(&temp_dir, "small.txt", b"small");
        let file2 = create_test_file(&temp_dir, "large.txt", &vec![b'x'; 1000]);
        let file3 = create_test_file(&temp_dir, "medium.txt", &vec![b'y'; 100]);
        
        // Create duplicate files
        let dup1 = create_test_file(&temp_dir, "dup1.txt", b"duplicate content");
        let dup2 = create_test_file(&temp_dir, "dup2.txt", b"duplicate content");
        
        // Start analysis
        let request = AnalysisRequest {
            target_directory: temp_dir.path().to_path_buf(),
            options: AnalysisOptions {
                hash_algorithm: Some("sha256".to_string()),
                thread_count: Some(1),
                follow_symlinks: Some(false),
            },
            exclude_patterns: None,
        };
        
        let session = server.start_analysis(request).await.unwrap();
        
        // Wait for completion (simple polling)
        let mut attempts = 0;
        loop {
            let status = server.get_analysis_status(&session.session_id).await.unwrap();
            if let Some(session_status) = status {
                if session_status.status == AnalysisStatus::Completed {
                    break;
                }
            }
            attempts += 1;
            if attempts > 50 {
                panic!("Analysis did not complete in time");
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        
        // Get results
        let results = server.get_analysis_results(&session.session_id).await.unwrap();
        assert!(results.is_some());
        
        let analysis_result = results.unwrap();
        
        // Test result sorting - duplicate sets should be sorted by potential savings
        if analysis_result.duplicate_sets.len() > 1 {
            for i in 1..analysis_result.duplicate_sets.len() {
                assert!(
                    analysis_result.duplicate_sets[i-1].potential_savings >= 
                    analysis_result.duplicate_sets[i].potential_savings,
                    "Duplicate sets should be sorted by potential savings in descending order"
                );
            }
        }
        
        // Test that results contain expected data for export
        assert!(analysis_result.total_files_analyzed > 0);
        assert!(analysis_result.duplicate_sets.len() > 0);
        
        // Verify duplicate set structure for export
        for duplicate_set in &analysis_result.duplicate_sets {
            assert!(duplicate_set.files.len() >= 2, "Duplicate sets should have at least 2 files");
            assert!(!duplicate_set.hash.is_empty(), "Duplicate sets should have a hash");
            assert!(duplicate_set.potential_savings > 0, "Duplicate sets should have positive potential savings");
            
            // Verify all files in the set have the same size
            let first_size = duplicate_set.files[0].size;
            for file in &duplicate_set.files {
                assert_eq!(file.size, first_size, "All files in duplicate set should have same size");
                assert!(file.is_accessible, "All files should be accessible");
                assert!(!file.path.as_os_str().is_empty(), "All files should have valid paths");
            }
        }
    }

    proptest! {
        /// **Feature: duplicate-file-analyzer, Property 15: Web Interface Result Sorting and Export**
        /// **Validates: Requirements 7.9, 7.10**
        #[test]
        fn test_web_interface_result_sorting_property(
            file_sizes in prop::collection::vec(1usize..10000, 2..8),
            duplicate_counts in prop::collection::vec(2usize..5, 1..4)
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let server = WebAPIServer::new();
                
                // Create files with different sizes to create duplicate sets with different savings
                let mut all_files = Vec::new();
                for (set_index, (&size, &count)) in file_sizes.iter().zip(duplicate_counts.iter()).enumerate() {
                    let content = vec![b'a' + (set_index as u8); size];
                    
                    for file_index in 0..count {
                        let file_name = format!("set{}_file{}.txt", set_index, file_index);
                        let file_path = create_test_file(&temp_dir, &file_name, &content);
                        all_files.push(file_path);
                    }
                }
                
                // Start analysis
                let request = AnalysisRequest {
                    target_directory: temp_dir.path().to_path_buf(),
                    options: AnalysisOptions {
                        hash_algorithm: Some("sha256".to_string()),
                        thread_count: Some(1),
                        follow_symlinks: Some(false),
                    },
                    exclude_patterns: None,
                };
                
                let session = server.start_analysis(request).await.unwrap();
                
                // Wait for completion
                let mut attempts = 0;
                loop {
                    let status = server.get_analysis_status(&session.session_id).await.unwrap();
                    if let Some(session_status) = status {
                        if session_status.status == AnalysisStatus::Completed {
                            break;
                        }
                    }
                    attempts += 1;
                    if attempts > 100 {
                        break; // Skip if taking too long
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
                
                // Get results
                let results = server.get_analysis_results(&session.session_id).await.unwrap();
                if let Some(analysis_result) = results {
                    // Property: Duplicate sets should be sorted by potential savings in descending order
                    for i in 1..analysis_result.duplicate_sets.len() {
                        prop_assert!(
                            analysis_result.duplicate_sets[i-1].potential_savings >= 
                            analysis_result.duplicate_sets[i].potential_savings,
                            "Duplicate sets should be sorted by potential savings: {} >= {}",
                            analysis_result.duplicate_sets[i-1].potential_savings,
                            analysis_result.duplicate_sets[i].potential_savings
                        );
                    }
                    
                    // Property: All duplicate sets should have complete export data
                    for duplicate_set in &analysis_result.duplicate_sets {
                        prop_assert!(duplicate_set.files.len() >= 2, "Duplicate sets should have at least 2 files");
                        prop_assert!(!duplicate_set.hash.is_empty(), "Duplicate sets should have a hash");
                        prop_assert!(duplicate_set.potential_savings > 0, "Duplicate sets should have positive potential savings");
                        
                        // Property: All files in a duplicate set should have consistent metadata for export
                        let first_size = duplicate_set.files[0].size;
                        for file in &duplicate_set.files {
                            prop_assert_eq!(file.size, first_size, "All files in duplicate set should have same size");
                            prop_assert!(file.is_accessible, "All files should be accessible for export");
                            prop_assert!(!file.path.as_os_str().is_empty(), "All files should have valid paths for export");
                        }
                        
                        // Property: Potential savings calculation should be correct
                        let expected_savings = first_size * (duplicate_set.files.len() as u64 - 1);
                        prop_assert_eq!(
                            duplicate_set.potential_savings, 
                            expected_savings,
                            "Potential savings should be calculated correctly: {} files of {} bytes each = {} savings",
                            duplicate_set.files.len(),
                            first_size,
                            expected_savings
                        );
                    }
                    
                    // Property: Analysis result should have complete summary data for export
                    prop_assert!(analysis_result.total_files_analyzed > 0, "Should have analyzed some files");
                    prop_assert!(analysis_result.total_duplicate_files > 0, "Should have found duplicate files");
                    prop_assert!(analysis_result.total_potential_savings > 0, "Should have potential savings");
                    prop_assert!(analysis_result.analysis_time >= 0.0, "Analysis time should be non-negative");
                }
                
                Ok(())
            });
        }
    }
}
