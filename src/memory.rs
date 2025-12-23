//! Memory management utilities for efficient processing of large directories

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;

/// Memory usage monitor that tracks current memory consumption
#[derive(Debug, Clone)]
pub struct MemoryMonitor {
    /// Current estimated memory usage in bytes
    current_usage: Arc<AtomicUsize>,
    /// Maximum allowed memory usage in bytes
    max_memory: usize,
    /// Memory usage threshold for triggering cleanup (percentage of max_memory)
    cleanup_threshold: f64,
    /// Last cleanup time
    last_cleanup: Arc<std::sync::Mutex<Instant>>,
}

impl MemoryMonitor {
    /// Create a new memory monitor
    pub fn new(max_memory: usize) -> Self {
        Self {
            current_usage: Arc::new(AtomicUsize::new(0)),
            max_memory,
            cleanup_threshold: 0.8, // Trigger cleanup at 80% of max memory
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// Create a new memory monitor with custom cleanup threshold
    pub fn with_threshold(max_memory: usize, cleanup_threshold: f64) -> Self {
        Self {
            current_usage: Arc::new(AtomicUsize::new(0)),
            max_memory,
            cleanup_threshold: cleanup_threshold.clamp(0.1, 0.95),
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// Add to current memory usage estimate
    pub fn add_usage(&self, bytes: usize) {
        self.current_usage.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Subtract from current memory usage estimate
    pub fn subtract_usage(&self, bytes: usize) {
        self.current_usage.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Get current memory usage estimate
    pub fn current_usage(&self) -> usize {
        self.current_usage.load(Ordering::Relaxed)
    }

    /// Get maximum allowed memory usage
    pub fn max_memory(&self) -> usize {
        self.max_memory
    }

    /// Get memory usage as percentage of maximum
    pub fn usage_percentage(&self) -> f64 {
        if self.max_memory == 0 {
            0.0
        } else {
            (self.current_usage() as f64 / self.max_memory as f64) * 100.0
        }
    }

    /// Check if memory usage is above cleanup threshold
    pub fn should_cleanup(&self) -> bool {
        self.usage_percentage() >= (self.cleanup_threshold * 100.0)
    }

    /// Check if memory usage is critically high (above 95% of max)
    pub fn is_memory_critical(&self) -> bool {
        self.usage_percentage() >= 95.0
    }

    /// Reset memory usage counter
    pub fn reset(&self) {
        self.current_usage.store(0, Ordering::Relaxed);
    }

    /// Update last cleanup time
    pub fn mark_cleanup(&self) {
        if let Ok(mut last_cleanup) = self.last_cleanup.lock() {
            *last_cleanup = Instant::now();
        }
    }

    /// Get time since last cleanup
    pub fn time_since_cleanup(&self) -> Duration {
        if let Ok(last_cleanup) = self.last_cleanup.lock() {
            last_cleanup.elapsed()
        } else {
            Duration::from_secs(0)
        }
    }

    /// Start a background memory monitoring task
    pub fn start_monitoring(&self) -> tokio::task::JoinHandle<()> {
        let monitor = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5)); // Check every 5 seconds
            
            loop {
                interval.tick().await;
                
                let usage_pct = monitor.usage_percentage();
                if usage_pct > 90.0 {
                    eprintln!("Warning: High memory usage detected: {:.1}% of maximum", usage_pct);
                }
                
                if monitor.is_memory_critical() {
                    eprintln!("Critical: Memory usage is critically high: {:.1}% of maximum", usage_pct);
                    eprintln!("Consider reducing batch size or increasing memory limit");
                }
            }
        })
    }
}

impl Default for MemoryMonitor {
    fn default() -> Self {
        Self::new(1024 * 1024 * 1024) // 1GB default
    }
}

/// Batch processor for handling large collections of items with memory constraints
#[derive(Debug)]
pub struct BatchProcessor<T> {
    /// Items to process
    items: Vec<T>,
    /// Current batch size
    batch_size: usize,
    /// Memory monitor
    memory_monitor: MemoryMonitor,
    /// Estimated memory per item in bytes
    memory_per_item: usize,
}

impl<T> BatchProcessor<T> {
    /// Create a new batch processor
    pub fn new(items: Vec<T>, batch_size: usize, memory_monitor: MemoryMonitor) -> Self {
        Self {
            items,
            batch_size,
            memory_monitor,
            memory_per_item: 1024, // Default estimate: 1KB per item
        }
    }

    /// Create a new batch processor with memory estimation
    pub fn with_memory_estimate(
        items: Vec<T>,
        batch_size: usize,
        memory_monitor: MemoryMonitor,
        memory_per_item: usize,
    ) -> Self {
        Self {
            items,
            batch_size,
            memory_monitor,
            memory_per_item,
        }
    }

    /// Get the total number of items
    pub fn total_items(&self) -> usize {
        self.items.len()
    }

    /// Get the current batch size
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Adjust batch size based on current memory usage
    pub fn adjust_batch_size(&mut self) {
        let usage_pct = self.memory_monitor.usage_percentage();
        
        if usage_pct > 80.0 {
            // Reduce batch size if memory usage is high
            self.batch_size = (self.batch_size as f64 * 0.7) as usize;
            self.batch_size = self.batch_size.max(10); // Minimum batch size
        } else if usage_pct < 40.0 && self.batch_size < 10000 {
            // Increase batch size if memory usage is low
            self.batch_size = (self.batch_size as f64 * 1.3) as usize;
            self.batch_size = self.batch_size.min(10000); // Maximum batch size
        }
    }

    /// Process items in batches with a provided async function
    pub async fn process_batches<F, Fut, R, E>(&mut self, mut processor: F) -> Result<Vec<R>, E>
    where
        F: FnMut(Vec<T>) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<R>, E>>,
        T: Clone,
    {
        let mut results = Vec::new();
        let mut start_idx = 0;

        while start_idx < self.items.len() {
            // Adjust batch size based on memory usage
            self.adjust_batch_size();

            let end_idx = (start_idx + self.batch_size).min(self.items.len());
            let batch: Vec<T> = self.items[start_idx..end_idx].to_vec();
            
            // Estimate memory usage for this batch
            let batch_memory = batch.len() * self.memory_per_item;
            self.memory_monitor.add_usage(batch_memory);

            // Process the batch
            match processor(batch).await {
                Ok(mut batch_results) => {
                    results.append(&mut batch_results);
                }
                Err(e) => {
                    // Clean up memory tracking on error
                    self.memory_monitor.subtract_usage(batch_memory);
                    return Err(e);
                }
            }

            // Clean up memory tracking after processing
            self.memory_monitor.subtract_usage(batch_memory);

            // Check if we should trigger cleanup
            if self.memory_monitor.should_cleanup() {
                self.memory_monitor.mark_cleanup();
                // Force garbage collection hint (not guaranteed to work)
                // In a real implementation, you might want to implement custom cleanup logic
            }

            start_idx = end_idx;
        }

        Ok(results)
    }

    /// Process items in batches and collect results, with memory-aware processing
    pub async fn process_with_memory_limit<F, Fut, R, E>(
        &mut self,
        mut processor: F,
    ) -> Result<Vec<R>, E>
    where
        F: FnMut(Vec<T>) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<R>, E>>,
        T: Clone,
    {
        let mut results = Vec::new();
        let mut start_idx = 0;

        while start_idx < self.items.len() {
            // Wait if memory usage is critically high
            while self.memory_monitor.is_memory_critical() {
                eprintln!("Memory usage critical, waiting before processing next batch...");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Adjust batch size based on current memory usage
            self.adjust_batch_size();

            let end_idx = (start_idx + self.batch_size).min(self.items.len());
            let batch: Vec<T> = self.items[start_idx..end_idx].to_vec();
            
            // Estimate memory usage for this batch
            let batch_memory = batch.len() * self.memory_per_item;
            
            // Check if this batch would exceed memory limits
            if self.memory_monitor.current_usage() + batch_memory > self.memory_monitor.max_memory() {
                // Reduce batch size and try again
                self.batch_size = self.batch_size / 2;
                if self.batch_size == 0 {
                    self.batch_size = 1;
                }
                continue;
            }

            self.memory_monitor.add_usage(batch_memory);

            // Process the batch
            match processor(batch).await {
                Ok(mut batch_results) => {
                    results.append(&mut batch_results);
                }
                Err(e) => {
                    // Clean up memory tracking on error
                    self.memory_monitor.subtract_usage(batch_memory);
                    return Err(e);
                }
            }

            // Clean up memory tracking after processing
            self.memory_monitor.subtract_usage(batch_memory);

            start_idx = end_idx;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[test]
    fn test_memory_monitor_basic_functionality() {
        let monitor = MemoryMonitor::new(1000);
        
        assert_eq!(monitor.current_usage(), 0);
        assert_eq!(monitor.max_memory(), 1000);
        assert_eq!(monitor.usage_percentage(), 0.0);
        assert!(!monitor.should_cleanup());
        assert!(!monitor.is_memory_critical());
        
        // Add some usage
        monitor.add_usage(500);
        assert_eq!(monitor.current_usage(), 500);
        assert_eq!(monitor.usage_percentage(), 50.0);
        assert!(!monitor.should_cleanup()); // Below 80% threshold
        
        // Add more usage to trigger cleanup threshold
        monitor.add_usage(350);
        assert_eq!(monitor.current_usage(), 850);
        assert_eq!(monitor.usage_percentage(), 85.0);
        assert!(monitor.should_cleanup()); // Above 80% threshold
        assert!(!monitor.is_memory_critical()); // Below 95% threshold
        
        // Add more to trigger critical threshold
        monitor.add_usage(100);
        assert_eq!(monitor.current_usage(), 950);
        assert_eq!(monitor.usage_percentage(), 95.0);
        assert!(monitor.is_memory_critical());
        
        // Subtract usage
        monitor.subtract_usage(200);
        assert_eq!(monitor.current_usage(), 750);
        assert_eq!(monitor.usage_percentage(), 75.0);
        assert!(!monitor.should_cleanup());
        assert!(!monitor.is_memory_critical());
        
        // Reset
        monitor.reset();
        assert_eq!(monitor.current_usage(), 0);
        assert_eq!(monitor.usage_percentage(), 0.0);
    }

    #[test]
    fn test_memory_monitor_with_custom_threshold() {
        let monitor = MemoryMonitor::with_threshold(1000, 0.6); // 60% threshold
        
        monitor.add_usage(500);
        assert!(!monitor.should_cleanup()); // 50% < 60%
        
        monitor.add_usage(150);
        assert!(monitor.should_cleanup()); // 65% > 60%
    }

    #[tokio::test]
    async fn test_batch_processor_basic_functionality() {
        let items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let monitor = MemoryMonitor::new(10000);
        let mut processor = BatchProcessor::new(items, 3, monitor);
        
        assert_eq!(processor.total_items(), 10);
        assert_eq!(processor.batch_size(), 3);
        
        // Process batches
        let results = processor.process_batches(|batch| async move {
            // Simulate processing by returning the sum of each batch
            Ok::<Vec<i32>, Box<dyn std::error::Error + Send + Sync>>(vec![batch.iter().sum::<i32>()])
        }).await.unwrap();
        
        // Should have 4 batches: [1,2,3], [4,5,6], [7,8,9], [10]
        // Sums: 6, 15, 24, 10
        assert_eq!(results, vec![6, 15, 24, 10]);
    }

    #[tokio::test]
    async fn test_batch_processor_memory_adjustment() {
        let items = vec![1; 1000]; // 1000 items
        let monitor = MemoryMonitor::new(1000); // Small memory limit
        let mut processor = BatchProcessor::with_memory_estimate(items, 100, monitor.clone(), 10);
        
        // Simulate high memory usage
        monitor.add_usage(850); // 85% usage
        
        processor.adjust_batch_size();
        
        // Batch size should be reduced due to high memory usage
        assert!(processor.batch_size() < 100);
        
        // Reduce memory usage
        monitor.subtract_usage(600); // Now at 25% usage
        
        processor.adjust_batch_size();
        
        // Batch size should increase due to low memory usage
        // (but might still be smaller than original due to previous reduction)
    }

    #[tokio::test]
    async fn test_batch_processor_with_memory_limit() {
        let items = vec![1; 100];
        let monitor = MemoryMonitor::new(500); // Small memory limit
        let mut processor = BatchProcessor::with_memory_estimate(items, 50, monitor, 5); // 5 bytes per item
        
        let results = processor.process_with_memory_limit(|batch| async move {
            // Simulate some processing time
            sleep(Duration::from_millis(1)).await;
            Ok::<Vec<usize>, Box<dyn std::error::Error + Send + Sync>>(vec![batch.len()])
        }).await.unwrap();
        
        // Should process all items in batches
        let total_processed: usize = results.iter().sum();
        assert_eq!(total_processed, 100);
    }

    #[tokio::test]
    async fn test_batch_processor_error_handling() {
        let items = vec![1, 2, 3, 4, 5];
        let monitor = MemoryMonitor::new(10000);
        let mut processor = BatchProcessor::new(items, 2, monitor.clone());
        
        let result = processor.process_batches(|batch| async move {
            if batch.contains(&3) {
                Err::<Vec<i32>, &str>("Error processing batch with 3")
            } else {
                Ok(vec![batch.iter().sum::<i32>()])
            }
        }).await;
        
        // Should return error when processing batch containing 3
        assert!(result.is_err());
        
        // Memory usage should be cleaned up after error
        assert_eq!(monitor.current_usage(), 0);
    }
}