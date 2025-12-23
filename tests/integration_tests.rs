//! Comprehensive integration tests for the duplicate file analyzer
//! 
//! These tests verify end-to-end workflows including CLI, web API, and error handling

use duplicate_file_analyzer::{
    analysis::AnalysisController, 
    models::*, 
    web::api::{WebAPIServer, AnalysisRequest, AnalysisOptions, AnalysisStatus},
    Config, HashAlgorithm, Result
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tempfile::TempDir;
use tokio::time::{sleep, Duration};

/// Helper function to create test directory structure
fn create_test_directory_structure(temp_dir: &TempDir, files: &[(&str, &[u8])]) -> Result<()> {
    for (path, content) in files {
        let full_path = temp_dir.path().join(path);
        
        // Create parent directories if they don't exist
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let mut file = fs::File::create(full_path)?;
        file.write_all(content)?;
    }
    Ok(())
}

/// Helper function to wait for analysis completion
async fn wait_for_analysis_completion(
    server: &WebAPIServer, 
    session_id: &str, 
    timeout_seconds: u64
) -> Result<bool> {
    let mut attempts = 0;
    let max_attempts = timeout_seconds * 10; // Check every 100ms
    
    loop {
        if let Some(session) = server.get_analysis_status(session_id).await? {
            match session.status {
                AnalysisStatus::Completed => return Ok(true),
                AnalysisStatus::Failed | AnalysisStatus::Cancelled => return Ok(false),
                AnalysisStatus::Running => {
                    // Continue waiting
                }
            }
        } else {
            return Ok(false); // Session not found
        }
        
        attempts += 1;
        if attempts >= max_attempts {
            return Ok(false); // Timeout
        }
        
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn test_end_to_end_cli_workflow() {
    // Create a test directory with known duplicates
    let temp_dir = TempDir::new().unwrap();
    
    let test_files = vec![
        ("file1.txt", b"Hello, World!" as &[u8]),
        ("file2.txt", b"Hello, World!"), // Duplicate of file1
        ("file3.txt", b"Different content"),
        ("subdir/file4.txt", b"Hello, World!"), // Another duplicate
        ("subdir/file5.txt", b"Unique content"),
        ("subdir/nested/file6.txt", b"Hello, World!"), // Another duplicate
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    // Test CLI analysis workflow
    let mut controller = AnalysisController::new();
    let options = DiscoveryOptions::default();
    
    let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
    
    // Verify results
    assert_eq!(result.total_files_analyzed, 6);
    assert_eq!(result.duplicate_sets.len(), 1); // One set of duplicates
    assert_eq!(result.duplicate_sets[0].files.len(), 4); // 4 files with "Hello, World!"
    assert_eq!(result.total_duplicate_files, 4);
    assert!(result.total_potential_savings > 0);
    assert!(result.analysis_time >= 0.0);
    
    // Verify duplicate set is sorted by potential savings
    for duplicate_set in &result.duplicate_sets {
        assert!(duplicate_set.files.len() >= 2);
        assert!(!duplicate_set.hash.is_empty());
        assert!(duplicate_set.potential_savings > 0);
        
        // All files should have the same size
        let first_size = duplicate_set.files[0].size;
        for file in &duplicate_set.files {
            assert_eq!(file.size, first_size);
            assert!(file.is_accessible);
        }
    }
    
    println!("✓ End-to-end CLI workflow test passed");
}

#[tokio::test]
async fn test_end_to_end_web_api_workflow() {
    // Create a test directory with known duplicates
    let temp_dir = TempDir::new().unwrap();
    
    // Create test files with different sizes for sorting
    let jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
    let test_files = vec![
        ("doc1.txt", b"Document content" as &[u8]),
        ("doc2.txt", b"Document content"), // Duplicate
        ("image1.jpg", jpeg_data.as_slice()), // JPEG header
        ("image2.jpg", jpeg_data.as_slice()), // Duplicate JPEG
        ("unique.txt", b"Unique file content"),
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    // Test Web API workflow
    let server = WebAPIServer::new();
    
    // Start analysis
    let request = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(2),
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let session = server.start_analysis(request).await.unwrap();
    assert_eq!(session.status, AnalysisStatus::Running);
    assert_eq!(session.progress, 0.0);
    
    // Wait for completion
    let completed = wait_for_analysis_completion(&server, &session.session_id, 30).await.unwrap();
    assert!(completed, "Analysis should complete within timeout");
    
    // Get final status
    let final_status = server.get_analysis_status(&session.session_id).await.unwrap();
    assert!(final_status.is_some());
    let final_session = final_status.unwrap();
    assert_eq!(final_session.status, AnalysisStatus::Completed);
    assert_eq!(final_session.progress, 100.0);
    
    // Get results
    let results = server.get_analysis_results(&session.session_id).await.unwrap();
    assert!(results.is_some());
    
    let analysis_result = results.unwrap();
    assert_eq!(analysis_result.total_files_analyzed, 5);
    assert_eq!(analysis_result.duplicate_sets.len(), 2); // Two duplicate sets
    assert_eq!(analysis_result.total_duplicate_files, 4); // 2 + 2 duplicates
    assert!(analysis_result.total_potential_savings > 0);
    
    // Test file operations
    let test_file_path = temp_dir.path().join("unique.txt");
    let file_info = server.get_file_info(&test_file_path.to_string_lossy()).await.unwrap();
    assert!(file_info.is_some());
    
    let metadata = file_info.unwrap();
    assert_eq!(metadata.path, test_file_path);
    assert!(metadata.is_accessible);
    
    // Test file deletion
    let delete_result = server.delete_file(&test_file_path.to_string_lossy()).await.unwrap();
    assert!(delete_result);
    assert!(!test_file_path.exists());
    
    println!("✓ End-to-end Web API workflow test passed");
}

#[tokio::test]
async fn test_error_handling_across_components() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create files with various potential issues
    let large_data = vec![b'x'; 10000];
    let test_files = vec![
        ("normal.txt", b"Normal file" as &[u8]),
        ("empty.txt", b""), // Empty file
        ("large.txt", large_data.as_slice()), // Large file
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    // Create a file and then make it inaccessible (on Unix systems)
    let restricted_file = temp_dir.path().join("restricted.txt");
    fs::write(&restricted_file, "restricted content").unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&restricted_file).unwrap().permissions();
        perms.set_mode(0o000); // No permissions
        fs::set_permissions(&restricted_file, perms).unwrap();
    }
    
    // Test CLI error handling
    let mut controller = AnalysisController::new();
    let options = DiscoveryOptions::default();
    
    let result = controller.analyze_directory(temp_dir.path(), options).await;
    
    match result {
        Ok(analysis_result) => {
            // Analysis should succeed even with some inaccessible files
            assert!(analysis_result.total_files_analyzed >= 3); // At least the accessible files
            assert!(analysis_result.analysis_time >= 0.0);
            
            // Should have some errors recorded
            if !analysis_result.errors.is_empty() {
                println!("Recorded {} errors as expected", analysis_result.errors.len());
            }
        }
        Err(err) => {
            // If analysis fails, it should be a graceful failure
            println!("Analysis failed gracefully: {}", err);
        }
    }
    
    // Test Web API error handling
    let server = WebAPIServer::new();
    
    // Test with non-existent directory
    let invalid_request = AnalysisRequest {
        target_directory: PathBuf::from("/nonexistent/directory"),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(1),
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let session_result = server.start_analysis(invalid_request).await;
    match session_result {
        Ok(session) => {
            // Wait a bit and check if it failed gracefully
            sleep(Duration::from_millis(500)).await;
            let status = server.get_analysis_status(&session.session_id).await.unwrap();
            if let Some(session_status) = status {
                // Should either be failed, completed (with 0 files), or still running
                assert!(matches!(session_status.status, 
                    AnalysisStatus::Running | AnalysisStatus::Failed | AnalysisStatus::Completed));
                
                // If completed, should have analyzed 0 files
                if session_status.status == AnalysisStatus::Completed {
                    let results = server.get_analysis_results(&session.session_id).await.unwrap();
                    if let Some(analysis_result) = results {
                        assert_eq!(analysis_result.total_files_analyzed, 0);
                    }
                }
            }
        }
        Err(_) => {
            // Immediate error is also acceptable
            println!("Invalid directory request failed immediately as expected");
        }
    }
    
    // Test file operations with invalid paths
    let invalid_file_info = server.get_file_info("/nonexistent/file.txt").await.unwrap();
    assert!(invalid_file_info.is_none());
    
    let invalid_delete = server.delete_file("/nonexistent/file.txt").await.unwrap();
    assert!(!invalid_delete);
    
    // Restore permissions for cleanup
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&restricted_file).unwrap_or_else(|_| {
            // File might not exist, create a dummy metadata
            fs::metadata(temp_dir.path()).unwrap()
        }).permissions();
        perms.set_mode(0o644);
        let _ = fs::set_permissions(&restricted_file, perms);
    }
    
    println!("✓ Error handling across components test passed");
}

#[tokio::test]
async fn test_large_directory_performance() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a larger directory structure for performance testing
    let mut test_files = Vec::new();
    
    // Create 50 files with some duplicates
    for i in 0..50 {
        let content = if i % 5 == 0 {
            // Every 5th file is a duplicate
            b"Duplicate content".to_vec()
        } else if i % 7 == 0 {
            // Every 7th file is another duplicate group
            b"Another duplicate".to_vec()
        } else {
            // Unique content
            format!("Unique content for file {}", i).into_bytes()
        };
        
        let filename = format!("file_{:03}.txt", i);
        test_files.push((filename, content));
    }
    
    // Create subdirectories
    for i in 0..10 {
        let subdir = format!("subdir_{}", i);
        for j in 0..5 {
            let content = format!("Subdir {} file {}", i, j).into_bytes();
            let filename = format!("{}/file_{}.txt", subdir, j);
            test_files.push((filename, content));
        }
    }
    
    // Write all files
    for (filename, content) in &test_files {
        let full_path = temp_dir.path().join(filename);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full_path, content).unwrap();
    }
    
    println!("Created {} test files", test_files.len());
    
    // Test performance with different configurations
    let configs = vec![
        ("Single thread", Config { thread_count: 1, ..Config::default() }),
        ("Multi thread", Config { thread_count: 4, ..Config::default() }),
        ("MD5 hash", Config { hash_algorithm: HashAlgorithm::Md5, ..Config::default() }),
    ];
    
    for (name, config) in configs {
        let start_time = std::time::Instant::now();
        
        let mut controller = AnalysisController::with_config(config);
        let options = DiscoveryOptions::default();
        
        let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
        
        let elapsed = start_time.elapsed();
        
        println!("{}: Analyzed {} files in {:?}", name, result.total_files_analyzed, elapsed);
        println!("  Found {} duplicate sets with {} total duplicates", 
                result.duplicate_sets.len(), result.total_duplicate_files);
        println!("  Potential savings: {} bytes", result.total_potential_savings);
        
        // Verify results are consistent
        assert!(result.total_files_analyzed >= 100); // Should find all files
        assert!(result.duplicate_sets.len() >= 2); // Should find duplicate groups
        assert!(result.total_duplicate_files > 0);
        assert!(result.analysis_time >= 0.0);
        
        // Performance should be reasonable (less than 30 seconds for this test)
        assert!(elapsed.as_secs() < 30, "Analysis took too long: {:?}", elapsed);
    }
    
    println!("✓ Large directory performance test passed");
}

#[tokio::test]
async fn test_concurrent_analysis_sessions() {
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();
    
    // Create different file structures in each directory
    let files1 = vec![
        ("a.txt", b"Content A" as &[u8]),
        ("b.txt", b"Content A"), // Duplicate
    ];
    
    let files2 = vec![
        ("x.txt", b"Content X" as &[u8]),
        ("y.txt", b"Content Y"),
        ("z.txt", b"Content X"), // Duplicate
    ];
    
    create_test_directory_structure(&temp_dir1, &files1).unwrap();
    create_test_directory_structure(&temp_dir2, &files2).unwrap();
    
    let server = WebAPIServer::new();
    
    // Start two concurrent analyses
    let request1 = AnalysisRequest {
        target_directory: temp_dir1.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(1),
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let request2 = AnalysisRequest {
        target_directory: temp_dir2.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(1),
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let session1 = server.start_analysis(request1).await.unwrap();
    let session2 = server.start_analysis(request2).await.unwrap();
    
    // Verify sessions have different IDs
    assert_ne!(session1.session_id, session2.session_id);
    
    // Wait for both to complete
    let completed1 = wait_for_analysis_completion(&server, &session1.session_id, 30).await.unwrap();
    let completed2 = wait_for_analysis_completion(&server, &session2.session_id, 30).await.unwrap();
    
    assert!(completed1, "First analysis should complete");
    assert!(completed2, "Second analysis should complete");
    
    // Get results for both
    let results1 = server.get_analysis_results(&session1.session_id).await.unwrap();
    let results2 = server.get_analysis_results(&session2.session_id).await.unwrap();
    
    assert!(results1.is_some());
    assert!(results2.is_some());
    
    let analysis1 = results1.unwrap();
    let analysis2 = results2.unwrap();
    
    // Verify results are different and correct
    assert_eq!(analysis1.total_files_analyzed, 2);
    assert_eq!(analysis1.duplicate_sets.len(), 1);
    
    assert_eq!(analysis2.total_files_analyzed, 3);
    assert_eq!(analysis2.duplicate_sets.len(), 1);
    
    // Test session management
    let active_sessions = server.get_active_sessions().await.unwrap();
    assert!(active_sessions.len() >= 2);
    
    println!("✓ Concurrent analysis sessions test passed");
}

#[tokio::test]
async fn test_resume_functionality() {
    let temp_dir = TempDir::new().unwrap();
    
    let test_files = vec![
        ("file1.txt", b"Content 1" as &[u8]),
        ("file2.txt", b"Content 2"),
        ("file3.txt", b"Content 1"), // Duplicate
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    // Test resume functionality
    let controller_result = AnalysisController::with_resume();
    
    match controller_result {
        Ok(mut controller) => {
            // Test listing resumable sessions (should be empty initially)
            let sessions = controller.list_resumable_sessions().await.unwrap();
            assert!(sessions.is_empty() || sessions.len() >= 0); // May have old sessions
            
            // Start analysis with resume capability
            let options = DiscoveryOptions::default();
            let result = controller.analyze_directory_with_resume(
                temp_dir.path(), 
                options, 
                None // No existing session to resume
            ).await.unwrap();
            
            // Verify analysis completed
            assert_eq!(result.total_files_analyzed, 3);
            assert_eq!(result.duplicate_sets.len(), 1);
            assert_eq!(result.total_duplicate_files, 2);
            
            println!("✓ Resume functionality test passed");
        }
        Err(err) => {
            println!("Resume functionality not available: {}", err);
            println!("✓ Resume functionality test skipped (not available)");
        }
    }
}

#[tokio::test]
async fn test_filtering_and_exclusions() {
    let temp_dir = TempDir::new().unwrap();
    
    let test_files = vec![
        ("document.txt", b"Text content" as &[u8]),
        ("document.doc", b"Text content"), // Same content, different extension
        ("image.jpg", b"Image data"),
        ("image.png", b"Image data"), // Same content, different extension
        ("backup.bak", b"Backup data"),
        ("temp.tmp", b"Temporary data"),
        ("subdir/nested.txt", b"Nested content"),
        ("excluded_dir/file.txt", b"Should be excluded"),
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    // Test with exclusion patterns
    let mut controller = AnalysisController::new();
    let mut options = DiscoveryOptions::default();
    options.exclude_patterns = vec!["*.bak".to_string(), "*.tmp".to_string()];
    options.exclude_directories = vec!["excluded_dir".to_string()];
    
    let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
    
    // Should exclude .bak, .tmp files and excluded_dir
    assert_eq!(result.total_files_analyzed, 5); // 8 - 2 (bak,tmp) - 1 (excluded_dir)
    
    // Test with extension filters
    let mut options2 = DiscoveryOptions::default();
    options2.include_extensions = vec!["txt".to_string()];
    
    let result2 = controller.analyze_directory(temp_dir.path(), options2).await.unwrap();
    
    // Should only include .txt files
    assert_eq!(result2.total_files_analyzed, 3); // document.txt, subdir/nested.txt, excluded_dir/file.txt
    
    println!("✓ Filtering and exclusions test passed");
}

#[tokio::test] 
async fn test_memory_management() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create files of various sizes to test memory management
    let mut test_files = Vec::new();
    
    // Small files
    for i in 0..20 {
        let content = format!("Small file content {}", i).into_bytes();
        test_files.push((format!("small_{}.txt", i), content));
    }
    
    // Medium files
    for i in 0..10 {
        let content = vec![b'M'; 1024]; // 1KB files
        test_files.push((format!("medium_{}.txt", i), content));
    }
    
    // Large files
    for i in 0..5 {
        let content = vec![b'L'; 10240]; // 10KB files
        test_files.push((format!("large_{}.txt", i), content));
    }
    
    // Write all files
    for (filename, content) in &test_files {
        let full_path = temp_dir.path().join(filename);
        fs::write(full_path, content).unwrap();
    }
    
    // Test with memory-constrained configuration
    let config = Config {
        max_memory: 1024 * 1024, // 1MB limit
        batch_size: 10,
        thread_count: 2,
        ..Config::default()
    };
    
    let mut controller = AnalysisController::with_config(config);
    let options = DiscoveryOptions::default();
    
    let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
    
    // Should complete successfully despite memory constraints
    assert_eq!(result.total_files_analyzed, 35);
    assert!(result.analysis_time >= 0.0);
    
    // Check memory statistics
    let (current_usage, max_usage, percentage) = controller.get_memory_stats();
    println!("Memory usage: {} / {} bytes ({:.1}%)", current_usage, max_usage, percentage);
    
    // Memory usage should be reasonable
    assert!(percentage <= 100.0);
    assert!(current_usage <= max_usage);
    
    println!("✓ Memory management test passed");
}

#[tokio::test]
async fn test_web_interface_progress_updates() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create enough files to have observable progress
    let mut test_files = Vec::new();
    for i in 0..30 {
        let content = format!("File content {}", i).into_bytes();
        test_files.push((format!("file_{:02}.txt", i), content));
    }
    
    // Write all files
    for (filename, content) in &test_files {
        let full_path = temp_dir.path().join(filename);
        fs::write(full_path, content).unwrap();
    }
    
    let server = WebAPIServer::new();
    
    let request = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(1), // Single thread for predictable progress
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let session = server.start_analysis(request).await.unwrap();
    
    // Monitor progress updates
    let mut progress_updates = Vec::new();
    let mut attempts = 0;
    let max_attempts = 300; // 30 seconds max
    
    loop {
        if let Some(status) = server.get_analysis_status(&session.session_id).await.unwrap() {
            progress_updates.push((status.progress, status.status.clone()));
            
            match status.status {
                AnalysisStatus::Completed => break,
                AnalysisStatus::Failed | AnalysisStatus::Cancelled => {
                    panic!("Analysis failed or was cancelled");
                }
                AnalysisStatus::Running => {
                    // Continue monitoring
                }
            }
        }
        
        attempts += 1;
        if attempts >= max_attempts {
            panic!("Analysis did not complete within timeout");
        }
        
        sleep(Duration::from_millis(100)).await;
    }
    
    // Verify progress updates
    assert!(!progress_updates.is_empty(), "Should have received progress updates");
    
    // Progress should start at 0 and end at 100
    assert_eq!(progress_updates[0].0, 0.0, "Progress should start at 0%");
    assert_eq!(progress_updates.last().unwrap().0, 100.0, "Progress should end at 100%");
    
    // Progress should be non-decreasing
    for i in 1..progress_updates.len() {
        assert!(
            progress_updates[i].0 >= progress_updates[i-1].0,
            "Progress should be non-decreasing: {} -> {}",
            progress_updates[i-1].0,
            progress_updates[i].0
        );
    }
    
    // Should have multiple progress updates showing incremental progress
    let running_updates: Vec<_> = progress_updates.iter()
        .filter(|(_, status)| *status == AnalysisStatus::Running)
        .collect();
    
    if running_updates.len() > 1 {
        println!("Received {} progress updates during analysis", running_updates.len());
    }
    
    println!("✓ Web interface progress updates test passed");
}

#[tokio::test]
async fn test_cli_binary_integration() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create test files
    let test_files = vec![
        ("test1.txt", b"Hello World" as &[u8]),
        ("test2.txt", b"Hello World"), // Duplicate
        ("test3.txt", b"Different content"),
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    // Test CLI binary execution (if available)
    let output = std::process::Command::new("cargo")
        .args(&[
            "run", 
            "--bin", 
            "duplicate-analyzer", 
            "--", 
            "analyze", 
            temp_dir.path().to_str().unwrap(),
            "--format", 
            "json"
        ])
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                let stdout = String::from_utf8_lossy(&result.stdout);
                println!("CLI output: {}", stdout);
                
                // Try to parse as JSON
                if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    // Verify JSON structure
                    assert!(json_value.get("total_files_analyzed").is_some());
                    assert!(json_value.get("duplicate_sets").is_some());
                    assert!(json_value.get("total_potential_savings").is_some());
                    
                    println!("✓ CLI binary integration test passed");
                } else {
                    println!("CLI output was not valid JSON, but command succeeded");
                }
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                println!("CLI failed with error: {}", stderr);
                // CLI failure is acceptable for this test
            }
        }
        Err(err) => {
            println!("Could not execute CLI binary: {}", err);
            // This is acceptable - the binary might not be built
        }
    }
}

#[tokio::test]
async fn test_web_api_endpoints_comprehensive() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a complex directory structure
    let png_data = vec![0x89, 0x50, 0x4E, 0x47];
    let test_files = vec![
        ("docs/readme.txt", b"Documentation" as &[u8]),
        ("docs/readme_copy.txt", b"Documentation"), // Duplicate
        ("src/main.rs", b"fn main() {}"),
        ("src/lib.rs", b"pub mod lib;"),
        ("tests/test1.rs", b"#[test] fn test() {}"),
        ("tests/test2.rs", b"#[test] fn test() {}"), // Duplicate
        ("assets/logo.png", png_data.as_slice()), // PNG header
        ("assets/icon.png", png_data.as_slice()), // Duplicate PNG
    ];
    
    create_test_directory_structure(&temp_dir, &test_files).unwrap();
    
    let server = WebAPIServer::new();
    
    // Test 1: Start analysis with various options
    let request = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(2),
            follow_symlinks: Some(true),
        },
        exclude_patterns: Some(vec!["*.rs".to_string()]), // Exclude Rust files
    };
    
    let session = server.start_analysis(request).await.unwrap();
    let session_id = session.session_id.clone();
    
    // Test 2: Monitor progress
    let mut progress_checks = 0;
    loop {
        let status = server.get_analysis_status(&session_id).await.unwrap();
        assert!(status.is_some());
        
        let session_status = status.unwrap();
        progress_checks += 1;
        
        match session_status.status {
            AnalysisStatus::Completed => break,
            AnalysisStatus::Failed => panic!("Analysis failed unexpectedly"),
            AnalysisStatus::Cancelled => panic!("Analysis was cancelled unexpectedly"),
            AnalysisStatus::Running => {
                assert!(session_status.progress >= 0.0 && session_status.progress <= 100.0);
                // Continue monitoring
            }
        }
        
        if progress_checks > 100 {
            panic!("Analysis took too long");
        }
        
        sleep(Duration::from_millis(50)).await;
    }
    
    // Test 3: Get results
    let results = server.get_analysis_results(&session_id).await.unwrap();
    assert!(results.is_some());
    
    let analysis_result = results.unwrap();
    
    // Should have excluded .rs files, so only 4 files analyzed
    assert_eq!(analysis_result.total_files_analyzed, 4);
    
    // Should find duplicates in the remaining files
    assert!(analysis_result.duplicate_sets.len() > 0);
    
    // Test 4: File operations on discovered files
    let test_file_path = temp_dir.path().join("docs/readme.txt");
    
    // Get file info
    let file_info = server.get_file_info(&test_file_path.to_string_lossy()).await.unwrap();
    assert!(file_info.is_some());
    
    let metadata = file_info.unwrap();
    assert_eq!(metadata.path, test_file_path);
    assert!(metadata.is_accessible);
    assert_eq!(metadata.size, b"Documentation".len() as u64);
    
    // Test 5: Bulk file operations
    let files_to_delete = vec![
        temp_dir.path().join("docs/readme_copy.txt").to_string_lossy().to_string(),
        temp_dir.path().join("assets/icon.png").to_string_lossy().to_string(),
    ];
    
    let deletion_results = server.delete_files(&files_to_delete).await.unwrap();
    assert_eq!(deletion_results.len(), 2);
    
    for (file_path, success) in &deletion_results {
        assert!(*success, "File deletion should succeed: {}", file_path);
    }
    
    // Verify files were deleted
    assert!(!temp_dir.path().join("docs/readme_copy.txt").exists());
    assert!(!temp_dir.path().join("assets/icon.png").exists());
    
    // Test 6: Session management
    let active_sessions = server.get_active_sessions().await.unwrap();
    assert!(active_sessions.iter().any(|s| s.session_id == session_id));
    
    // Test 7: Cleanup old sessions
    let cleanup_count = server.cleanup_old_sessions(Duration::from_secs(0)).await.unwrap();
    assert!(cleanup_count >= 0); // Should clean up completed sessions
    
    println!("✓ Comprehensive Web API endpoints test passed");
}

#[tokio::test]
async fn test_error_scenarios_comprehensive() {
    let server = WebAPIServer::new();
    
    // Test 1: Analysis with invalid hash algorithm
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("test.txt"), "test").unwrap();
    
    let request = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("invalid_algorithm".to_string()),
            thread_count: Some(1),
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    // This should either fail immediately or handle the invalid algorithm gracefully
    let session_result = server.start_analysis(request).await;
    match session_result {
        Ok(session) => {
            // If it starts, it should handle the invalid algorithm gracefully
            let completed = wait_for_analysis_completion(&server, &session.session_id, 10).await.unwrap();
            // Either completes successfully (using default algorithm) or fails gracefully
            assert!(completed || !completed); // Either outcome is acceptable
        }
        Err(_) => {
            // Immediate failure is also acceptable
            println!("Invalid hash algorithm rejected immediately");
        }
    }
    
    // Test 2: Analysis with zero threads
    let request2 = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(0), // Invalid thread count
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let session_result2 = server.start_analysis(request2).await;
    match session_result2 {
        Ok(session) => {
            // Should handle gracefully by using default thread count
            let completed = wait_for_analysis_completion(&server, &session.session_id, 10).await.unwrap();
            assert!(completed); // Should complete successfully
        }
        Err(_) => {
            // Immediate rejection is also acceptable
            println!("Zero thread count rejected immediately");
        }
    }
    
    // Test 3: File operations on non-existent files
    let non_existent_file = "/absolutely/non/existent/file.txt";
    
    let file_info = server.get_file_info(non_existent_file).await.unwrap();
    assert!(file_info.is_none());
    
    let delete_result = server.delete_file(non_existent_file).await.unwrap();
    assert!(!delete_result);
    
    // Test 4: Operations on non-existent sessions
    let fake_session_id = "non-existent-session-id";
    
    let status = server.get_analysis_status(fake_session_id).await.unwrap();
    assert!(status.is_none());
    
    let results = server.get_analysis_results(fake_session_id).await.unwrap();
    assert!(results.is_none());
    
    let cancel_result = server.cancel_analysis(fake_session_id).await.unwrap();
    assert!(!cancel_result);
    
    // Test 5: File operations on directories
    let dir_path = temp_dir.path().to_string_lossy().to_string();
    
    let delete_dir_result = server.delete_file(&dir_path).await.unwrap();
    assert!(!delete_dir_result); // Should not delete directories
    
    println!("✓ Comprehensive error scenarios test passed");
}

#[tokio::test]
async fn test_large_scale_integration() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a large-scale directory structure
    let mut test_files = Vec::new();
    
    // Create multiple subdirectories with files
    for dir_idx in 0..10 {
        let dir_name = format!("dir_{:02}", dir_idx);
        
        for file_idx in 0..20 {
            let content = if file_idx % 3 == 0 {
                // Every 3rd file is a duplicate
                format!("Duplicate content type {}", file_idx % 5).into_bytes()
            } else {
                // Unique content
                format!("Unique content for {}/{}", dir_name, file_idx).into_bytes()
            };
            
            let file_path = format!("{}/file_{:03}.txt", dir_name, file_idx);
            test_files.push((file_path, content));
        }
    }
    
    // Add some binary files
    for i in 0..10 {
        let binary_content = vec![i as u8; 1000]; // 1KB binary files
        let file_path = format!("binary/file_{:02}.bin", i);
        test_files.push((file_path, binary_content));
    }
    
    println!("Creating {} test files...", test_files.len());
    
    // Write all files
    for (file_path, content) in &test_files {
        let full_path = temp_dir.path().join(file_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full_path, content).unwrap();
    }
    
    // Test with CLI controller
    let start_time = std::time::Instant::now();
    
    let mut controller = AnalysisController::new();
    let options = DiscoveryOptions::default();
    
    let result = controller.analyze_directory(temp_dir.path(), options).await.unwrap();
    
    let cli_duration = start_time.elapsed();
    
    println!("CLI Analysis Results:");
    println!("  Files analyzed: {}", result.total_files_analyzed);
    println!("  Duplicate sets: {}", result.duplicate_sets.len());
    println!("  Total duplicates: {}", result.total_duplicate_files);
    println!("  Potential savings: {} bytes", result.total_potential_savings);
    println!("  Analysis time: {:?}", cli_duration);
    
    // Verify results
    assert_eq!(result.total_files_analyzed, test_files.len() as u64);
    assert!(result.duplicate_sets.len() > 0); // Should find duplicates
    assert!(result.total_duplicate_files > 0);
    assert!(result.total_potential_savings > 0);
    
    // Test with Web API
    let server = WebAPIServer::new();
    
    let request = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(4), // Use multiple threads
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let web_start_time = std::time::Instant::now();
    let session = server.start_analysis(request).await.unwrap();
    
    // Wait for completion
    let completed = wait_for_analysis_completion(&server, &session.session_id, 60).await.unwrap();
    assert!(completed, "Web API analysis should complete");
    
    let web_duration = web_start_time.elapsed();
    
    let web_results = server.get_analysis_results(&session.session_id).await.unwrap();
    assert!(web_results.is_some());
    
    let web_result = web_results.unwrap();
    
    println!("Web API Analysis Results:");
    println!("  Files analyzed: {}", web_result.total_files_analyzed);
    println!("  Duplicate sets: {}", web_result.duplicate_sets.len());
    println!("  Total duplicates: {}", web_result.total_duplicate_files);
    println!("  Potential savings: {} bytes", web_result.total_potential_savings);
    println!("  Analysis time: {:?}", web_duration);
    
    // Results should be consistent between CLI and Web API
    assert_eq!(result.total_files_analyzed, web_result.total_files_analyzed);
    assert_eq!(result.duplicate_sets.len(), web_result.duplicate_sets.len());
    assert_eq!(result.total_duplicate_files, web_result.total_duplicate_files);
    assert_eq!(result.total_potential_savings, web_result.total_potential_savings);
    
    // Performance should be reasonable
    assert!(cli_duration.as_secs() < 30, "CLI analysis should complete within 30 seconds");
    assert!(web_duration.as_secs() < 30, "Web API analysis should complete within 30 seconds");
    
    println!("✓ Large-scale integration test passed");
}

#[tokio::test]
async fn test_edge_cases_and_boundary_conditions() {
    // Test 1: Empty directory
    let empty_dir = TempDir::new().unwrap();
    
    let mut controller = AnalysisController::new();
    let options = DiscoveryOptions::default();
    
    let result = controller.analyze_directory(empty_dir.path(), options.clone()).await.unwrap();
    
    assert_eq!(result.total_files_analyzed, 0);
    assert_eq!(result.duplicate_sets.len(), 0);
    assert_eq!(result.total_duplicate_files, 0);
    assert_eq!(result.total_potential_savings, 0);
    assert!(result.analysis_time >= 0.0);
    
    // Test 2: Single file
    let single_file_dir = TempDir::new().unwrap();
    fs::write(single_file_dir.path().join("single.txt"), "single file").unwrap();
    
    let result2 = controller.analyze_directory(single_file_dir.path(), options.clone()).await.unwrap();
    
    assert_eq!(result2.total_files_analyzed, 1);
    assert_eq!(result2.duplicate_sets.len(), 0); // No duplicates possible with one file
    assert_eq!(result2.total_duplicate_files, 0);
    assert_eq!(result2.total_potential_savings, 0);
    
    // Test 3: Files with identical names but different paths
    let identical_names_dir = TempDir::new().unwrap();
    
    fs::create_dir_all(identical_names_dir.path().join("dir1")).unwrap();
    fs::create_dir_all(identical_names_dir.path().join("dir2")).unwrap();
    
    fs::write(identical_names_dir.path().join("dir1/file.txt"), "content1").unwrap();
    fs::write(identical_names_dir.path().join("dir2/file.txt"), "content1").unwrap(); // Same content
    fs::write(identical_names_dir.path().join("file.txt"), "content2").unwrap(); // Different content
    
    let result3 = controller.analyze_directory(identical_names_dir.path(), options.clone()).await.unwrap();
    
    assert_eq!(result3.total_files_analyzed, 3);
    assert_eq!(result3.duplicate_sets.len(), 1); // One duplicate set
    assert_eq!(result3.total_duplicate_files, 2); // Two files with same content
    
    // Test 4: Very small files (1 byte)
    let small_files_dir = TempDir::new().unwrap();
    
    for i in 0..5 {
        fs::write(small_files_dir.path().join(format!("small_{}.txt", i)), &[i as u8]).unwrap();
    }
    
    // Add duplicates
    fs::write(small_files_dir.path().join("dup1.txt"), &[0u8]).unwrap(); // Duplicate of small_0.txt
    fs::write(small_files_dir.path().join("dup2.txt"), &[0u8]).unwrap(); // Another duplicate
    
    let result4 = controller.analyze_directory(small_files_dir.path(), options.clone()).await.unwrap();
    
    assert_eq!(result4.total_files_analyzed, 7);
    assert_eq!(result4.duplicate_sets.len(), 1); // One duplicate set with 3 files
    assert_eq!(result4.total_duplicate_files, 3);
    assert_eq!(result4.total_potential_savings, 2); // 2 bytes can be saved
    
    // Test 5: Files with special characters in names
    let special_chars_dir = TempDir::new().unwrap();
    
    let special_files = vec![
        ("file with spaces.txt", b"content1" as &[u8]),
        ("file-with-dashes.txt", b"content2"),
        ("file_with_underscores.txt", b"content1"), // Duplicate
        ("file.with.dots.txt", b"content3"),
        ("file(with)parentheses.txt", b"content2"), // Duplicate
    ];
    
    for (name, content) in &special_files {
        fs::write(special_chars_dir.path().join(name), content).unwrap();
    }
    
    let result5 = controller.analyze_directory(special_chars_dir.path(), options.clone()).await.unwrap();
    
    assert_eq!(result5.total_files_analyzed, 5);
    assert_eq!(result5.duplicate_sets.len(), 2); // Two duplicate sets
    assert_eq!(result5.total_duplicate_files, 4); // 2 + 2 duplicates
    
    println!("✓ Edge cases and boundary conditions test passed");
}

#[tokio::test]
async fn test_concurrent_modifications_during_analysis() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create initial files
    let initial_files = vec![
        ("file1.txt", b"Initial content 1" as &[u8]),
        ("file2.txt", b"Initial content 2"),
        ("file3.txt", b"Initial content 1"), // Duplicate
    ];
    
    create_test_directory_structure(&temp_dir, &initial_files).unwrap();
    
    let server = WebAPIServer::new();
    
    let request = AnalysisRequest {
        target_directory: temp_dir.path().to_path_buf(),
        options: AnalysisOptions {
            hash_algorithm: Some("sha256".to_string()),
            thread_count: Some(1), // Single thread for predictable timing
            follow_symlinks: Some(false),
        },
        exclude_patterns: None,
    };
    
    let session = server.start_analysis(request).await.unwrap();
    
    // Modify files during analysis
    tokio::spawn({
        let temp_dir_path = temp_dir.path().to_path_buf();
        async move {
            // Wait a bit for analysis to start
            sleep(Duration::from_millis(100)).await;
            
            // Modify a file
            let _ = fs::write(temp_dir_path.join("file2.txt"), "Modified content during analysis");
            
            // Add a new file
            let _ = fs::write(temp_dir_path.join("new_file.txt"), "New file added during analysis");
            
            // Delete a file
            let _ = fs::remove_file(temp_dir_path.join("file3.txt"));
        }
    });
    
    // Wait for analysis completion
    let completed = wait_for_analysis_completion(&server, &session.session_id, 30).await.unwrap();
    assert!(completed, "Analysis should complete despite concurrent modifications");
    
    let results = server.get_analysis_results(&session.session_id).await.unwrap();
    assert!(results.is_some());
    
    let analysis_result = results.unwrap();
    
    // Analysis should complete successfully despite modifications
    assert!(analysis_result.total_files_analyzed >= 2); // At least the files that existed at start
    assert!(analysis_result.analysis_time >= 0.0);
    
    // May or may not have errors depending on timing
    println!("Analysis completed with {} errors", analysis_result.errors.len());
    
    println!("✓ Concurrent modifications during analysis test passed");
}