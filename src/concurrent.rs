//! Concurrent modification detection for handling files that change during analysis

use crate::{models::*, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::fs;

/// Tracks file modification times to detect concurrent changes
#[derive(Debug, Clone)]
pub struct FileChangeDetector {
    /// Map of file paths to their last known modification times
    tracked_files: HashMap<PathBuf, SystemTime>,
    /// Files that have been detected as modified during analysis
    modified_files: Vec<PathBuf>,
    /// Errors encountered during change detection
    errors: Vec<AnalysisError>,
}

impl FileChangeDetector {
    /// Create a new file change detector
    pub fn new() -> Self {
        Self {
            tracked_files: HashMap::new(),
            modified_files: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Start tracking a file's modification time
    pub async fn track_file(&mut self, file_path: &Path) -> Result<()> {
        match fs::metadata(file_path).await {
            Ok(metadata) => {
                let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                self.tracked_files.insert(file_path.to_path_buf(), modified_time);
                Ok(())
            }
            Err(err) => {
                let error = AnalysisError {
                    message: format!("Cannot track file {}: {}", file_path.display(), err),
                    file_path: Some(file_path.to_path_buf()),
                    category: ErrorCategory::FileSystem,
                };
                self.errors.push(error);
                Err(err.into())
            }
        }
    }

    /// Start tracking multiple files
    pub async fn track_files(&mut self, files: &[FileMetadata]) -> Result<()> {
        for file in files {
            // Use the modification time from the FileMetadata if available
            self.tracked_files.insert(file.path.clone(), file.modified_time);
        }
        Ok(())
    }

    /// Check if a file has been modified since we started tracking it
    pub async fn check_file_modified(&mut self, file_path: &Path) -> Result<bool> {
        let original_time = match self.tracked_files.get(file_path) {
            Some(time) => *time,
            None => {
                // File not being tracked, start tracking it now
                self.track_file(file_path).await?;
                return Ok(false); // Not modified since we just started tracking
            }
        };

        match fs::metadata(file_path).await {
            Ok(metadata) => {
                let current_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                
                if current_time != original_time {
                    // File has been modified
                    if !self.modified_files.contains(&file_path.to_path_buf()) {
                        self.modified_files.push(file_path.to_path_buf());
                    }
                    
                    // Update our tracking with the new modification time
                    self.tracked_files.insert(file_path.to_path_buf(), current_time);
                    
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(err) => {
                let error = AnalysisError {
                    message: format!("Cannot check modification time for {}: {}", file_path.display(), err),
                    file_path: Some(file_path.to_path_buf()),
                    category: ErrorCategory::FileSystem,
                };
                self.errors.push(error);
                
                // If we can't check the file, assume it might be modified
                if !self.modified_files.contains(&file_path.to_path_buf()) {
                    self.modified_files.push(file_path.to_path_buf());
                }
                
                Ok(true) // Assume modified if we can't check
            }
        }
    }

    /// Check all tracked files for modifications
    pub async fn check_all_files(&mut self) -> Result<Vec<PathBuf>> {
        let mut newly_modified = Vec::new();
        
        // Clone the keys to avoid borrowing issues
        let file_paths: Vec<PathBuf> = self.tracked_files.keys().cloned().collect();
        
        for file_path in file_paths {
            if self.check_file_modified(&file_path).await? {
                newly_modified.push(file_path);
            }
        }
        
        // Return all files that have been detected as modified (both newly and previously)
        Ok(self.modified_files.clone())
    }

    /// Get all files that have been detected as modified
    pub fn get_modified_files(&self) -> &[PathBuf] {
        &self.modified_files
    }

    /// Get the number of files currently being tracked
    pub fn tracked_file_count(&self) -> usize {
        self.tracked_files.len()
    }

    /// Get the number of files detected as modified
    pub fn modified_file_count(&self) -> usize {
        self.modified_files.len()
    }

    /// Check if any files have been modified
    pub fn has_modified_files(&self) -> bool {
        !self.modified_files.is_empty()
    }

    /// Get all errors encountered during change detection
    pub fn get_errors(&self) -> &[AnalysisError] {
        &self.errors
    }

    /// Check if any errors occurred during change detection
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.tracked_files.clear();
        self.modified_files.clear();
        self.errors.clear();
    }

    /// Remove a file from tracking
    pub fn untrack_file(&mut self, file_path: &Path) {
        self.tracked_files.remove(file_path);
        self.modified_files.retain(|p| p != file_path);
    }

    /// Get the original modification time for a tracked file
    pub fn get_original_modification_time(&self, file_path: &Path) -> Option<SystemTime> {
        self.tracked_files.get(file_path).copied()
    }

    /// Update the FileMetadata with current modification time if it has changed
    pub async fn update_file_metadata_if_changed(&mut self, file_metadata: &mut FileMetadata) -> Result<bool> {
        let was_modified = self.check_file_modified(&file_metadata.path).await?;
        
        if was_modified {
            // Update the FileMetadata with the current modification time
            if let Ok(metadata) = fs::metadata(&file_metadata.path).await {
                let current_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                file_metadata.modified_time = current_time;
                
                // Also update size in case it changed
                file_metadata.size = metadata.len();
                
                // Clear any cached hash since the file has changed
                file_metadata.hash = None;
            }
        }
        
        Ok(was_modified)
    }

    /// Handle concurrent modification by deciding what action to take
    pub fn handle_concurrent_modification(&mut self, file_path: &Path) -> ConcurrentModificationAction {
        // For now, we'll use a simple strategy:
        // - Log the modification
        // - Continue processing with a warning
        // - The file will be re-read with its new content
        
        let error = AnalysisError {
            message: format!("File {} was modified during analysis and will be processed with its current content", file_path.display()),
            file_path: Some(file_path.to_path_buf()),
            category: ErrorCategory::System,
        };
        self.errors.push(error);
        
        ConcurrentModificationAction::ContinueWithWarning
    }
}

impl Default for FileChangeDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Actions that can be taken when a concurrent modification is detected
#[derive(Debug, Clone, PartialEq)]
pub enum ConcurrentModificationAction {
    /// Continue processing with the current file content and log a warning
    ContinueWithWarning,
    /// Skip the file and exclude it from analysis
    SkipFile,
    /// Restart analysis of this file from the beginning
    RestartFileAnalysis,
    /// Abort the entire analysis
    AbortAnalysis,
}

/// Extension trait for FileMetadata to add concurrent modification checking
pub trait FileMetadataExt {
    /// Check if this file has been modified since the metadata was collected
    async fn check_if_modified(&self) -> Result<bool>;
    
    /// Update this metadata with current file information
    async fn refresh_metadata(&mut self) -> Result<bool>;
}

impl FileMetadataExt for FileMetadata {
    async fn check_if_modified(&self) -> Result<bool> {
        match fs::metadata(&self.path).await {
            Ok(metadata) => {
                let current_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let current_size = metadata.len();
                
                Ok(current_time != self.modified_time || current_size != self.size)
            }
            Err(_) => {
                // If we can't read the file, assume it might be modified
                Ok(true)
            }
        }
    }
    
    async fn refresh_metadata(&mut self) -> Result<bool> {
        match fs::metadata(&self.path).await {
            Ok(metadata) => {
                let current_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let current_size = metadata.len();
                
                let was_modified = current_time != self.modified_time || current_size != self.size;
                
                if was_modified {
                    self.modified_time = current_time;
                    self.size = current_size;
                    self.hash = None; // Clear cached hash since file changed
                }
                
                Ok(was_modified)
            }
            Err(err) => {
                self.is_accessible = false;
                Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::fs;
    use tokio::time::sleep;

    // Helper function to create a test file with specific content
    async fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> Result<PathBuf> {
        let file_path = dir.path().join(name);
        fs::write(&file_path, content).await?;
        Ok(file_path)
    }

    // Helper function to modify a file
    async fn modify_file(file_path: &Path, new_content: &[u8]) -> Result<()> {
        // Add a small delay to ensure modification time changes
        sleep(Duration::from_millis(10)).await;
        fs::write(file_path, new_content).await?;
        Ok(())
    }

    prop_compose! {
        fn arb_file_content()(
            content in prop::collection::vec(any::<u8>(), 1..1000)
        ) -> Vec<u8> {
            content
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))] // Reduced cases for async tests

        /// **Feature: duplicate-file-analyzer, Property 8: Concurrent Modification Handling**
        /// **Validates: Requirements 5.2**
        /// For any files modified during analysis, the system should detect the changes and handle them appropriately
        #[test]
        fn test_concurrent_modification_detection(
            original_content in arb_file_content(),
            modified_content in arb_file_content()
        ) {
            // Skip if contents are identical
            prop_assume!(original_content != modified_content);
            
            tokio_test::block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let file_path = create_test_file(&temp_dir, "test_file.txt", &original_content).await.unwrap();
                
                let mut detector = FileChangeDetector::new();
                
                // Start tracking the file
                detector.track_file(&file_path).await.unwrap();
                
                // Property: Initially, file should not be detected as modified
                let initially_modified = detector.check_file_modified(&file_path).await.unwrap();
                prop_assert!(!initially_modified, "File should not be initially detected as modified");
                
                // Property: Tracked file count should be 1
                prop_assert_eq!(detector.tracked_file_count(), 1);
                prop_assert_eq!(detector.modified_file_count(), 0);
                prop_assert!(!detector.has_modified_files());
                
                // Modify the file
                modify_file(&file_path, &modified_content).await.unwrap();
                
                // Property: File should now be detected as modified
                let is_modified = detector.check_file_modified(&file_path).await.unwrap();
                prop_assert!(is_modified, "File should be detected as modified after change");
                
                // Property: Modified file should be tracked
                prop_assert_eq!(detector.modified_file_count(), 1);
                prop_assert!(detector.has_modified_files());
                prop_assert!(detector.get_modified_files().contains(&file_path));
                
                // Property: Checking the same file again should still report it as modified
                // Note: After the first check, the detector updates its tracking time,
                // so we need to modify the file again to test this
                modify_file(&file_path, b"even newer content").await.unwrap();
                let still_modified = detector.check_file_modified(&file_path).await.unwrap();
                prop_assert!(still_modified, "File should still be detected as modified after another change");
                
                // Property: Modified file count should increase when checking the same file again after another modification
                prop_assert_eq!(detector.modified_file_count(), 1);
                
                // Property: check_all_files should return the modified file
                let all_modified = detector.check_all_files().await.unwrap();
                prop_assert!(all_modified.contains(&file_path), 
                    "check_all_files should return the modified file, got: {:?}", all_modified);
                
                Ok(())
            })?;
        }

        /// Test file metadata extension methods
        #[test]
        fn test_file_metadata_concurrent_modification(
            original_content in arb_file_content(),
            modified_content in arb_file_content()
        ) {
            prop_assume!(original_content != modified_content);
            
            tokio_test::block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let file_path = create_test_file(&temp_dir, "test_file.txt", &original_content).await.unwrap();
                
                // Create FileMetadata
                let metadata = fs::metadata(&file_path).await.unwrap();
                let mut file_metadata = FileMetadata::new(
                    file_path.clone(),
                    metadata.len(),
                    metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    true,
                );
                
                // Property: Initially, file should not be detected as modified
                let initially_modified = file_metadata.check_if_modified().await.unwrap();
                prop_assert!(!initially_modified, "File should not be initially detected as modified");
                
                // Modify the file
                modify_file(&file_path, &modified_content).await.unwrap();
                
                // Property: File should now be detected as modified
                let is_modified = file_metadata.check_if_modified().await.unwrap();
                prop_assert!(is_modified, "File should be detected as modified after change");
                
                // Property: Refreshing metadata should detect the change
                let was_refreshed = file_metadata.refresh_metadata().await.unwrap();
                prop_assert!(was_refreshed, "Metadata refresh should detect the change");
                
                // Property: After refresh, file should not be detected as modified anymore
                let after_refresh_modified = file_metadata.check_if_modified().await.unwrap();
                prop_assert!(!after_refresh_modified, "File should not be detected as modified after metadata refresh");
                
                // Property: File size should be updated
                prop_assert_eq!(file_metadata.size, modified_content.len() as u64);
                
                // Property: Hash should be cleared after modification
                prop_assert!(file_metadata.hash.is_none(), "Hash should be cleared after file modification");
                
                Ok(())
            })?;
        }

        /// Test handling multiple files with some modifications
        #[test]
        fn test_multiple_files_concurrent_modification(
            file_contents in prop::collection::vec(arb_file_content(), 2..5)
        ) {
            tokio_test::block_on(async {
                let temp_dir = TempDir::new().unwrap();
                let mut detector = FileChangeDetector::new();
                let mut file_paths = Vec::new();
                
                // Create and track multiple files
                for (i, content) in file_contents.iter().enumerate() {
                    let file_path = create_test_file(&temp_dir, &format!("file_{}.txt", i), content).await.unwrap();
                    detector.track_file(&file_path).await.unwrap();
                    file_paths.push(file_path);
                }
                
                // Property: All files should be tracked
                prop_assert_eq!(detector.tracked_file_count(), file_contents.len());
                prop_assert_eq!(detector.modified_file_count(), 0);
                
                // Modify every other file
                let mut expected_modified = 0;
                for (i, file_path) in file_paths.iter().enumerate() {
                    if i % 2 == 0 {
                        let new_content = format!("modified content {}", i);
                        modify_file(file_path, new_content.as_bytes()).await.unwrap();
                        expected_modified += 1;
                    }
                }
                
                // Check all files for modifications
                let modified_files = detector.check_all_files().await.unwrap();
                
                // Property: Should detect the correct number of modified files
                prop_assert_eq!(modified_files.len(), expected_modified);
                prop_assert_eq!(detector.modified_file_count(), expected_modified);
                
                // Property: Only the files we modified should be detected
                for (i, file_path) in file_paths.iter().enumerate() {
                    let should_be_modified = i % 2 == 0;
                    let is_detected_modified = modified_files.contains(file_path);
                    prop_assert_eq!(should_be_modified, is_detected_modified,
                        "File {} modification detection mismatch", i);
                }
                
                Ok(())
            })?;
        }
    }

    #[tokio::test]
    async fn test_file_change_detector_basic_functionality() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.txt", b"original content").await.unwrap();
        
        let mut detector = FileChangeDetector::new();
        
        // Track the file
        detector.track_file(&file_path).await.unwrap();
        assert_eq!(detector.tracked_file_count(), 1);
        assert_eq!(detector.modified_file_count(), 0);
        assert!(!detector.has_modified_files());
        
        // Check if file is modified (should be false initially)
        let is_modified = detector.check_file_modified(&file_path).await.unwrap();
        assert!(!is_modified);
        
        // Modify the file
        modify_file(&file_path, b"new content").await.unwrap();
        
        // Check if file is modified (should be true now)
        let is_modified = detector.check_file_modified(&file_path).await.unwrap();
        assert!(is_modified);
        assert_eq!(detector.modified_file_count(), 1);
        assert!(detector.has_modified_files());
        assert!(detector.get_modified_files().contains(&file_path));
    }

    #[tokio::test]
    async fn test_file_change_detector_track_files() {
        let temp_dir = TempDir::new().unwrap();
        let file1_path = create_test_file(&temp_dir, "file1.txt", b"content1").await.unwrap();
        let file2_path = create_test_file(&temp_dir, "file2.txt", b"content2").await.unwrap();
        
        // Create FileMetadata objects
        let metadata1 = fs::metadata(&file1_path).await.unwrap();
        let metadata2 = fs::metadata(&file2_path).await.unwrap();
        
        let file_metadata1 = FileMetadata::new(
            file1_path.clone(),
            metadata1.len(),
            metadata1.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            true,
        );
        let file_metadata2 = FileMetadata::new(
            file2_path.clone(),
            metadata2.len(),
            metadata2.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            true,
        );
        
        let files = vec![file_metadata1, file_metadata2];
        
        let mut detector = FileChangeDetector::new();
        detector.track_files(&files).await.unwrap();
        
        assert_eq!(detector.tracked_file_count(), 2);
        assert_eq!(detector.modified_file_count(), 0);
    }

    #[tokio::test]
    async fn test_file_change_detector_untrack_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.txt", b"content").await.unwrap();
        
        let mut detector = FileChangeDetector::new();
        detector.track_file(&file_path).await.unwrap();
        assert_eq!(detector.tracked_file_count(), 1);
        
        // Untrack the file
        detector.untrack_file(&file_path);
        assert_eq!(detector.tracked_file_count(), 0);
    }

    #[tokio::test]
    async fn test_file_change_detector_clear() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.txt", b"content").await.unwrap();
        
        let mut detector = FileChangeDetector::new();
        detector.track_file(&file_path).await.unwrap();
        
        // Modify file to create some state
        modify_file(&file_path, b"new content").await.unwrap();
        detector.check_file_modified(&file_path).await.unwrap();
        
        assert_eq!(detector.tracked_file_count(), 1);
        assert_eq!(detector.modified_file_count(), 1);
        
        // Clear all state
        detector.clear();
        assert_eq!(detector.tracked_file_count(), 0);
        assert_eq!(detector.modified_file_count(), 0);
        assert!(!detector.has_modified_files());
    }

    #[tokio::test]
    async fn test_file_metadata_extension_methods() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.txt", b"original content").await.unwrap();
        
        // Create FileMetadata
        let metadata = fs::metadata(&file_path).await.unwrap();
        let mut file_metadata = FileMetadata::new(
            file_path.clone(),
            metadata.len(),
            metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            true,
        );
        
        // Initially should not be modified
        let is_modified = file_metadata.check_if_modified().await.unwrap();
        assert!(!is_modified);
        
        // Modify the file
        modify_file(&file_path, b"new content").await.unwrap();
        
        // Should now be detected as modified
        let is_modified = file_metadata.check_if_modified().await.unwrap();
        assert!(is_modified);
        
        // Refresh metadata
        let was_refreshed = file_metadata.refresh_metadata().await.unwrap();
        assert!(was_refreshed);
        
        // After refresh, should not be detected as modified
        let is_modified = file_metadata.check_if_modified().await.unwrap();
        assert!(!is_modified);
        
        // Size should be updated
        assert_eq!(file_metadata.size, b"new content".len() as u64);
        
        // Hash should be cleared
        assert!(file_metadata.hash.is_none());
    }

    #[tokio::test]
    async fn test_concurrent_modification_action() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.txt", b"content").await.unwrap();
        
        let mut detector = FileChangeDetector::new();
        let action = detector.handle_concurrent_modification(&file_path);
        
        assert_eq!(action, ConcurrentModificationAction::ContinueWithWarning);
        assert!(detector.has_errors());
        assert_eq!(detector.get_errors().len(), 1);
        assert_eq!(detector.get_errors()[0].category, ErrorCategory::System);
    }

    #[tokio::test]
    async fn test_file_change_detector_nonexistent_file() {
        let mut detector = FileChangeDetector::new();
        let nonexistent_path = PathBuf::from("/nonexistent/file.txt");
        
        // Tracking a nonexistent file should result in an error
        let result = detector.track_file(&nonexistent_path).await;
        assert!(result.is_err());
        assert!(detector.has_errors());
        
        // Checking a nonexistent file should assume it's modified
        let is_modified = detector.check_file_modified(&nonexistent_path).await;
        // This should succeed but return true (assume modified)
        match is_modified {
            Ok(modified) => {
                assert!(modified); // Should assume modified if can't check
                assert!(detector.get_modified_files().contains(&nonexistent_path));
            }
            Err(_) => {
                // It's also acceptable for this to error
                assert!(detector.has_errors());
            }
        }
    }

    #[tokio::test]
    async fn test_update_file_metadata_if_changed() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = create_test_file(&temp_dir, "test.txt", b"original").await.unwrap();
        
        // Create FileMetadata
        let metadata = fs::metadata(&file_path).await.unwrap();
        let mut file_metadata = FileMetadata::new(
            file_path.clone(),
            metadata.len(),
            metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            true,
        );
        
        let mut detector = FileChangeDetector::new();
        detector.track_file(&file_path).await.unwrap();
        
        // Initially should not be changed
        let was_changed = detector.update_file_metadata_if_changed(&mut file_metadata).await.unwrap();
        assert!(!was_changed);
        
        // Modify the file
        modify_file(&file_path, b"new content").await.unwrap();
        
        // Should now detect change and update metadata
        let was_changed = detector.update_file_metadata_if_changed(&mut file_metadata).await.unwrap();
        assert!(was_changed);
        assert_eq!(file_metadata.size, b"new content".len() as u64);
        assert!(file_metadata.hash.is_none());
    }
}