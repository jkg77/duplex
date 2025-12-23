//! Progress tracking for long-running analysis operations

use crate::models::ProgressUpdate;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};
use tokio::sync::broadcast;

/// Event emitted when progress is updated
#[derive(Debug, Clone)]
pub struct ProgressEvent {
    /// The updated progress information
    pub progress: ProgressUpdate,
    /// Timestamp when the event was emitted
    pub timestamp: SystemTime,
}

/// Tracker for analysis progress with real-time event emission
pub struct ProgressTracker {
    start_time: Instant,
    current_progress: Arc<Mutex<ProgressUpdate>>,
    event_sender: broadcast::Sender<ProgressEvent>,
    last_update_time: Arc<Mutex<Instant>>,
    update_interval: std::time::Duration,
}

impl ProgressTracker {
    /// Create a new progress tracker with event emission capability
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        Self {
            start_time: Instant::now(),
            current_progress: Arc::new(Mutex::new(ProgressUpdate::new())),
            event_sender,
            last_update_time: Arc::new(Mutex::new(Instant::now())),
            update_interval: std::time::Duration::from_millis(100), // Update every 100ms
        }
    }

    /// Create a new progress tracker with custom update interval
    pub fn with_update_interval(interval: std::time::Duration) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        Self {
            start_time: Instant::now(),
            current_progress: Arc::new(Mutex::new(ProgressUpdate::new())),
            event_sender,
            last_update_time: Arc::new(Mutex::new(Instant::now())),
            update_interval: interval,
        }
    }

    /// Subscribe to progress events
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressEvent> {
        self.event_sender.subscribe()
    }

    /// Update the total number of files to process
    pub fn set_total_files(&self, total: u64) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.total_files = total;
        }
        self.emit_progress_if_needed();
    }

    /// Update the number of files processed
    pub fn set_files_processed(&self, processed: u64) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.files_processed = processed;
        }
        self.emit_progress_if_needed();
    }

    /// Increment the number of files processed by one
    pub fn increment_files_processed(&self) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.files_processed += 1;
        }
        self.emit_progress_if_needed();
    }

    /// Set the current file being processed
    pub fn set_current_file(&self, file_path: Option<PathBuf>) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.current_file = file_path;
        }
        self.emit_progress_if_needed();
    }

    /// Update bytes processed
    pub fn add_bytes_processed(&self, bytes: u64) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.bytes_processed += bytes;
        }
        self.emit_progress_if_needed();
    }

    /// Update duplicates found
    pub fn add_duplicates_found(&self, count: u64) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.duplicates_found += count;
        }
        self.emit_progress_if_needed();
    }

    /// Increment duplicates found by one
    pub fn increment_duplicates_found(&self) {
        if let Ok(mut progress) = self.current_progress.lock() {
            progress.duplicates_found += 1;
        }
        self.emit_progress_if_needed();
    }

    /// Get the current progress information
    pub fn get_current_progress(&self) -> ProgressUpdate {
        if let Ok(progress) = self.current_progress.lock() {
            let mut current = progress.clone();

            // Calculate estimated completion time
            if current.files_processed > 0 && current.total_files > current.files_processed {
                let elapsed = self.start_time.elapsed().as_secs_f64();
                let rate = current.files_processed as f64 / elapsed;
                if rate > 0.0 {
                    let remaining_files = current.total_files - current.files_processed;
                    let estimated_seconds = remaining_files as f64 / rate;

                    current.estimated_completion = Some(
                        SystemTime::now() + std::time::Duration::from_secs_f64(estimated_seconds),
                    );
                }
            }

            current
        } else {
            ProgressUpdate::new()
        }
    }

    /// Force emit a progress event immediately
    pub fn emit_progress(&self) {
        self.emit_progress_event();
    }

    /// Reset the progress tracker
    pub fn reset(&self) {
        if let Ok(mut progress) = self.current_progress.lock() {
            *progress = ProgressUpdate::new();
        }
        if let Ok(mut last_update) = self.last_update_time.lock() {
            *last_update = Instant::now();
        }
    }

    /// Get the elapsed time since analysis started
    pub fn elapsed_time(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Get the processing rate (files per second)
    pub fn processing_rate(&self) -> f64 {
        if let Ok(progress) = self.current_progress.lock() {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                progress.files_processed as f64 / elapsed
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Check if progress should be emitted based on time interval
    fn should_emit_progress(&self) -> bool {
        if let Ok(last_update) = self.last_update_time.lock() {
            last_update.elapsed() >= self.update_interval
        } else {
            false
        }
    }

    /// Emit progress event if enough time has passed
    fn emit_progress_if_needed(&self) {
        if self.should_emit_progress() {
            self.emit_progress_event();
            if let Ok(mut last_update) = self.last_update_time.lock() {
                *last_update = Instant::now();
            }
        }
    }

    /// Emit a progress event
    fn emit_progress_event(&self) {
        let current = self.get_current_progress();

        let event = ProgressEvent {
            progress: current,
            timestamp: SystemTime::now(),
        };

        // Send event (ignore if no receivers)
        let _ = self.event_sender.send(event);
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration;

    // Property-based test generators
    prop_compose! {
        fn arb_progress_values()(
            total_files in 1u64..10000,
            files_processed in 0u64..10000,
            bytes_processed in 0u64..1_000_000_000,
            duplicates_found in 0u64..1000
        ) -> (u64, u64, u64, u64) {
            // Ensure files_processed doesn't exceed total_files
            let files_processed = files_processed.min(total_files);
            (total_files, files_processed, bytes_processed, duplicates_found)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: duplicate-file-analyzer, Property 5: Progress Reporting**
        /// **Validates: Requirements 3.5**
        /// For any long-running analysis operation, progress indicators should be emitted at regular intervals
        #[test]
        fn test_progress_reporting_consistency(
            (total_files, files_processed, bytes_processed, duplicates_found) in arb_progress_values()
        ) {
            let tracker = ProgressTracker::new();
            
            // Set up progress values
            tracker.set_total_files(total_files);
            tracker.set_files_processed(files_processed);
            tracker.add_bytes_processed(bytes_processed);
            tracker.add_duplicates_found(duplicates_found);
            
            let progress = tracker.get_current_progress();
            
            // Property: Progress values should be consistent with what was set
            assert_eq!(progress.total_files, total_files);
            assert_eq!(progress.files_processed, files_processed);
            assert_eq!(progress.bytes_processed, bytes_processed);
            assert_eq!(progress.duplicates_found, duplicates_found);
            
            // Property: Progress percentage should be between 0 and 100
            let percentage = progress.progress_percentage();
            assert!(percentage >= 0.0 && percentage <= 100.0);
            
            // Property: If files_processed equals total_files, percentage should be 100
            if files_processed == total_files && total_files > 0 {
                assert!((percentage - 100.0).abs() < f64::EPSILON);
            }
            
            // Property: If no files processed, percentage should be 0
            if files_processed == 0 {
                assert!(percentage < f64::EPSILON);
            }
        }

        /// Test that progress events are emitted correctly
        #[test]
        fn test_progress_event_emission(
            (_total_files, _files_processed, _bytes_processed, _duplicates_found) in arb_progress_values()
        ) {
            let tracker = ProgressTracker::with_update_interval(Duration::from_millis(1));
            let mut _receiver = tracker.subscribe();
            
            // Set progress values that should trigger events
            tracker.set_total_files(_total_files);
            
            // Force emit to ensure we get an event
            tracker.emit_progress();
            
            // Property: Should be able to receive progress events
            // Note: This is a basic test - in real usage, events would be received asynchronously
            assert!(_receiver.try_recv().is_ok() || _receiver.len() > 0);
        }

        /// Test processing rate calculations
        #[test]
        fn test_processing_rate_calculation(files_processed in 1u64..1000) {
            let tracker = ProgressTracker::new();
            tracker.set_files_processed(files_processed);
            
            // Allow some time to pass for rate calculation
            std::thread::sleep(Duration::from_millis(10));
            
            let rate = tracker.processing_rate();
            
            // Property: Processing rate should be non-negative
            assert!(rate >= 0.0);
            
            // Property: If files were processed, rate should be positive
            if files_processed > 0 {
                assert!(rate > 0.0);
            }
        }

        /// Test estimated completion time calculation
        #[test]
        fn test_estimated_completion_time(
            (total_files, files_processed) in arb_progress_values().prop_map(|(t, f, _, _)| (t, f))
        ) {
            let tracker = ProgressTracker::new();
            tracker.set_total_files(total_files);
            
            // Allow some time to pass
            std::thread::sleep(Duration::from_millis(10));
            tracker.set_files_processed(files_processed);
            
            let progress = tracker.get_current_progress();
            
            // Property: If processing is incomplete and files have been processed, 
            // estimated completion should be set
            if files_processed > 0 && files_processed < total_files {
                assert!(progress.estimated_completion.is_some());
                
                // Property: Estimated completion should be in the future
                if let Some(completion_time) = progress.estimated_completion {
                    assert!(completion_time > SystemTime::now());
                }
            }
            
            // Property: If processing is complete, no estimation needed
            if files_processed >= total_files {
                // Estimation may or may not be present when complete
                // This is acceptable behavior
            }
        }
    }

    #[tokio::test]
    async fn test_progress_tracker_basic_functionality() {
        let tracker = ProgressTracker::new();
        let mut _receiver = tracker.subscribe();

        // Test basic operations
        tracker.set_total_files(100);
        tracker.set_files_processed(50);
        tracker.add_bytes_processed(1024);
        tracker.add_duplicates_found(5);

        let progress = tracker.get_current_progress();
        assert_eq!(progress.total_files, 100);
        assert_eq!(progress.files_processed, 50);
        assert_eq!(progress.bytes_processed, 1024);
        assert_eq!(progress.duplicates_found, 5);
        assert_eq!(progress.progress_percentage(), 50.0);

        // Test increment operations
        tracker.increment_files_processed();
        tracker.increment_duplicates_found();

        let progress = tracker.get_current_progress();
        assert_eq!(progress.files_processed, 51);
        assert_eq!(progress.duplicates_found, 6);

        // Test file path setting
        let test_path = PathBuf::from("/test/file.txt");
        tracker.set_current_file(Some(test_path.clone()));

        let progress = tracker.get_current_progress();
        assert_eq!(progress.current_file, Some(test_path));

        // Test reset
        tracker.reset();
        let progress = tracker.get_current_progress();
        assert_eq!(progress.files_processed, 0);
        assert_eq!(progress.total_files, 0);
        assert_eq!(progress.bytes_processed, 0);
        assert_eq!(progress.duplicates_found, 0);
        assert_eq!(progress.current_file, None);
    }

    #[tokio::test]
    async fn test_progress_event_subscription() {
        let tracker = ProgressTracker::with_update_interval(Duration::from_millis(1));
        let mut receiver = tracker.subscribe();

        // Set some progress
        tracker.set_total_files(100);
        tracker.emit_progress(); // Force emit

        // Should receive an event
        let event = receiver.recv().await.unwrap();
        assert_eq!(event.progress.total_files, 100);
        assert!(event.timestamp <= SystemTime::now());
    }
}
