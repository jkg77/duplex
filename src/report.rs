//! Report generation for analysis results

use crate::{models::AnalysisResult, Result};
use serde_json;
use std::path::Path;

/// Output format for reports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Text,
    Html,
    Csv,
}

/// Configuration for report formatting
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Whether to include detailed file information
    pub include_details: bool,
    /// Whether to sort by potential savings (descending)
    pub sort_by_savings: bool,
    /// Maximum number of duplicate sets to include (None for all)
    pub max_duplicate_sets: Option<usize>,
    /// Whether to include error information
    pub include_errors: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            include_details: true,
            sort_by_savings: true,
            max_duplicate_sets: None,
            include_errors: true,
        }
    }
}

/// Generator for analysis reports in various formats
pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    /// Create a new report generator with default configuration
    pub fn new() -> Self {
        Self {
            config: ReportConfig::default(),
        }
    }

    /// Create a new report generator with custom configuration
    pub fn with_config(config: ReportConfig) -> Self {
        Self { config }
    }

    /// Set the report configuration
    pub fn set_config(&mut self, config: ReportConfig) {
        self.config = config;
    }

    /// Generate report in the specified format
    pub fn generate_report(&self, result: &AnalysisResult, format: OutputFormat) -> Result<String> {
        // Sort duplicate sets by potential savings if configured
        let mut result = result.clone();
        if self.config.sort_by_savings {
            result.sort_by_savings();
        }

        // Limit duplicate sets if configured
        if let Some(max_sets) = self.config.max_duplicate_sets {
            result.duplicate_sets.truncate(max_sets);
        }

        match format {
            OutputFormat::Json => self.generate_json(&result),
            OutputFormat::Text => self.generate_text(&result),
            OutputFormat::Html => self.generate_html(&result),
            OutputFormat::Csv => self.generate_csv(&result),
        }
    }

    /// Generate JSON report
    pub fn generate_json(&self, result: &AnalysisResult) -> Result<String> {
        let json = if self.config.include_details {
            serde_json::to_string_pretty(result)?
        } else {
            // Create a simplified version without detailed file information
            let simplified = serde_json::json!({
                "summary": {
                    "total_files_analyzed": result.total_files_analyzed,
                    "total_duplicate_files": result.total_duplicate_files,
                    "total_potential_savings": result.total_potential_savings,
                    "duplicate_set_count": result.duplicate_sets.len(),
                    "analysis_time": result.analysis_time,
                    "duplicate_percentage": result.duplicate_percentage()
                },
                "duplicate_sets": result.duplicate_sets.iter().map(|ds| {
                    serde_json::json!({
                        "id": ds.id,
                        "file_count": ds.files.len(),
                        "total_size": ds.total_size,
                        "potential_savings": ds.potential_savings,
                        "hash": ds.hash
                    })
                }).collect::<Vec<_>>(),
                "errors": if self.config.include_errors { 
                    result.errors.as_slice() 
                } else { 
                    &[] as &[crate::models::AnalysisError] 
                }
            });
            serde_json::to_string_pretty(&simplified)?
        };
        Ok(json)
    }

    /// Generate human-readable text report
    pub fn generate_text(&self, result: &AnalysisResult) -> Result<String> {
        let mut report = String::new();

        // Header
        report.push_str("=== Duplicate File Analysis Report ===\n\n");

        // Summary
        report.push_str(&format!("Analysis Summary:\n"));
        report.push_str(&format!("  Total files analyzed: {}\n", result.total_files_analyzed));
        report.push_str(&format!("  Total duplicate files: {}\n", result.total_duplicate_files));
        report.push_str(&format!("  Duplicate sets found: {}\n", result.duplicate_sets.len()));
        report.push_str(&format!("  Duplicate percentage: {:.2}%\n", result.duplicate_percentage()));
        report.push_str(&format!("  Total potential savings: {} bytes ({:.2} MB)\n", 
            result.total_potential_savings, 
            result.total_potential_savings as f64 / (1024.0 * 1024.0)));
        report.push_str(&format!("  Analysis time: {:.2} seconds\n\n", result.analysis_time));

        // Duplicate sets
        if !result.duplicate_sets.is_empty() {
            report.push_str("Duplicate Sets (sorted by potential savings):\n\n");

            for (index, duplicate_set) in result.duplicate_sets.iter().enumerate() {
                report.push_str(&format!("{}. Duplicate Set {} ({} files, {} bytes each)\n",
                    index + 1,
                    duplicate_set.id,
                    duplicate_set.files.len(),
                    duplicate_set.total_size));
                
                report.push_str(&format!("   Potential savings: {} bytes ({:.2} MB)\n",
                    duplicate_set.potential_savings,
                    duplicate_set.potential_savings as f64 / (1024.0 * 1024.0)));
                
                report.push_str(&format!("   Hash: {}\n", duplicate_set.hash));

                if self.config.include_details {
                    report.push_str("   Files:\n");
                    for file in &duplicate_set.files {
                        report.push_str(&format!("     - {}\n", file.path.display()));
                        if let Some(modified) = file.modified_time.duration_since(std::time::UNIX_EPOCH).ok() {
                            report.push_str(&format!("       Modified: {} seconds since epoch\n", modified.as_secs()));
                        }
                    }
                }
                report.push('\n');
            }
        } else {
            report.push_str("No duplicate files found.\n\n");
        }

        // Errors
        if self.config.include_errors && !result.errors.is_empty() {
            report.push_str(&format!("Errors encountered ({}):\n", result.errors.len()));
            for error in &result.errors {
                report.push_str(&format!("  - {}", error.message));
                if let Some(path) = &error.file_path {
                    report.push_str(&format!(" ({})", path.display()));
                }
                report.push('\n');
            }
        }

        Ok(report)
    }

    /// Generate HTML report
    pub fn generate_html(&self, result: &AnalysisResult) -> Result<String> {
        let mut html = String::new();

        // HTML header
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("    <meta charset=\"UTF-8\">\n");
        html.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str("    <title>Duplicate File Analysis Report</title>\n");
        html.push_str("    <style>\n");
        html.push_str("        body { font-family: Arial, sans-serif; margin: 20px; }\n");
        html.push_str("        .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n");
        html.push_str("        .duplicate-set { border: 1px solid #ddd; margin-bottom: 15px; padding: 15px; border-radius: 5px; }\n");
        html.push_str("        .file-list { margin-left: 20px; }\n");
        html.push_str("        .file-item { margin: 5px 0; }\n");
        html.push_str("        .hash { font-family: monospace; font-size: 0.9em; color: #666; }\n");
        html.push_str("        .savings { color: #d9534f; font-weight: bold; }\n");
        html.push_str("        .error { color: #d9534f; }\n");
        html.push_str("    </style>\n");
        html.push_str("</head>\n<body>\n");

        // Title
        html.push_str("    <h1>Duplicate File Analysis Report</h1>\n");

        // Summary
        html.push_str("    <div class=\"summary\">\n");
        html.push_str("        <h2>Analysis Summary</h2>\n");
        html.push_str(&format!("        <p><strong>Total files analyzed:</strong> {}</p>\n", result.total_files_analyzed));
        html.push_str(&format!("        <p><strong>Total duplicate files:</strong> {}</p>\n", result.total_duplicate_files));
        html.push_str(&format!("        <p><strong>Duplicate sets found:</strong> {}</p>\n", result.duplicate_sets.len()));
        html.push_str(&format!("        <p><strong>Duplicate percentage:</strong> {:.2}%</p>\n", result.duplicate_percentage()));
        html.push_str(&format!("        <p><strong>Total potential savings:</strong> <span class=\"savings\">{} bytes ({:.2} MB)</span></p>\n", 
            result.total_potential_savings, 
            result.total_potential_savings as f64 / (1024.0 * 1024.0)));
        html.push_str(&format!("        <p><strong>Analysis time:</strong> {:.2} seconds</p>\n", result.analysis_time));
        html.push_str("    </div>\n");

        // Duplicate sets
        if !result.duplicate_sets.is_empty() {
            html.push_str("    <h2>Duplicate Sets (sorted by potential savings)</h2>\n");

            for (index, duplicate_set) in result.duplicate_sets.iter().enumerate() {
                html.push_str("    <div class=\"duplicate-set\">\n");
                html.push_str(&format!("        <h3>{}. Duplicate Set {} ({} files, {} bytes each)</h3>\n",
                    index + 1,
                    duplicate_set.id,
                    duplicate_set.files.len(),
                    duplicate_set.total_size));
                
                html.push_str(&format!("        <p><strong>Potential savings:</strong> <span class=\"savings\">{} bytes ({:.2} MB)</span></p>\n",
                    duplicate_set.potential_savings,
                    duplicate_set.potential_savings as f64 / (1024.0 * 1024.0)));
                
                html.push_str(&format!("        <p><strong>Hash:</strong> <span class=\"hash\">{}</span></p>\n", duplicate_set.hash));

                if self.config.include_details {
                    html.push_str("        <h4>Files:</h4>\n");
                    html.push_str("        <div class=\"file-list\">\n");
                    for file in &duplicate_set.files {
                        html.push_str(&format!("            <div class=\"file-item\">{}</div>\n", 
                            html_escape(&file.path.display().to_string())));
                    }
                    html.push_str("        </div>\n");
                }
                html.push_str("    </div>\n");
            }
        } else {
            html.push_str("    <p>No duplicate files found.</p>\n");
        }

        // Errors
        if self.config.include_errors && !result.errors.is_empty() {
            html.push_str(&format!("    <h2>Errors Encountered ({})</h2>\n", result.errors.len()));
            html.push_str("    <ul>\n");
            for error in &result.errors {
                html.push_str("        <li class=\"error\">");
                html.push_str(&html_escape(&error.message));
                if let Some(path) = &error.file_path {
                    html.push_str(&format!(" ({})", html_escape(&path.display().to_string())));
                }
                html.push_str("</li>\n");
            }
            html.push_str("    </ul>\n");
        }

        // HTML footer
        html.push_str("</body>\n</html>\n");

        Ok(html)
    }

    /// Generate CSV report
    pub fn generate_csv(&self, result: &AnalysisResult) -> Result<String> {
        let mut csv = String::new();

        // CSV header
        csv.push_str("duplicate_set_id,file_path,file_size,potential_savings,hash,modified_time\n");

        // Data rows
        for duplicate_set in &result.duplicate_sets {
            for file in &duplicate_set.files {
                csv.push_str(&format!("{},", csv_escape(&duplicate_set.id)));
                csv.push_str(&format!("{},", csv_escape(&file.path.display().to_string())));
                csv.push_str(&format!("{},", file.size));
                csv.push_str(&format!("{},", duplicate_set.potential_savings));
                csv.push_str(&format!("{},", csv_escape(&duplicate_set.hash)));
                
                // Format modified time
                if let Ok(duration) = file.modified_time.duration_since(std::time::UNIX_EPOCH) {
                    csv.push_str(&format!("{}", duration.as_secs()));
                } else {
                    csv.push_str("0");
                }
                csv.push('\n');
            }
        }

        Ok(csv)
    }

    /// Save report to file
    pub async fn save_to_file(&self, content: &str, file_path: &Path) -> Result<()> {
        tokio::fs::write(file_path, content).await?;
        Ok(())
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape HTML special characters
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Escape CSV special characters
fn csv_escape(input: &str) -> String {
    if input.contains(',') || input.contains('"') || input.contains('\n') {
        format!("\"{}\"", input.replace('"', "\"\""))
    } else {
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DuplicateSet, FileMetadata, AnalysisError, ErrorCategory};
    use std::path::PathBuf;
    use std::time::{UNIX_EPOCH, Duration};

    fn create_test_analysis_result() -> AnalysisResult {
        let mut result = AnalysisResult::new();
        result.total_files_analyzed = 100;
        result.analysis_time = 5.5;

        // Create test files
        let file1 = FileMetadata::new(
            PathBuf::from("/test/file1.txt"),
            1024,
            UNIX_EPOCH + Duration::from_secs(1000),
            true,
        );
        let file2 = FileMetadata::new(
            PathBuf::from("/test/file2.txt"),
            1024,
            UNIX_EPOCH + Duration::from_secs(2000),
            true,
        );

        // Create duplicate set
        let duplicate_set = DuplicateSet::new(
            vec![file1, file2],
            "abc123def456".to_string(),
        );

        result.add_duplicate_set(duplicate_set);

        // Add an error
        result.add_error(AnalysisError {
            message: "Permission denied".to_string(),
            file_path: Some(PathBuf::from("/test/restricted.txt")),
            category: ErrorCategory::Permission,
        });

        result
    }

    #[test]
    fn test_json_report_generation() {
        let generator = ReportGenerator::new();
        let result = create_test_analysis_result();

        let json_report = generator.generate_json(&result).unwrap();
        
        // Verify JSON is valid and contains expected data
        assert!(json_report.contains("total_files_analyzed"));
        assert!(json_report.contains("duplicate_sets"));
        assert!(json_report.contains("abc123def456"));
        assert!(json_report.contains("/test/file1.txt"));
    }

    #[test]
    fn test_text_report_generation() {
        let generator = ReportGenerator::new();
        let result = create_test_analysis_result();

        let text_report = generator.generate_text(&result).unwrap();
        
        // Verify text report contains expected sections
        assert!(text_report.contains("Duplicate File Analysis Report"));
        assert!(text_report.contains("Analysis Summary"));
        assert!(text_report.contains("Total files analyzed: 100"));
        assert!(text_report.contains("Duplicate Sets"));
        assert!(text_report.contains("/test/file1.txt"));
        assert!(text_report.contains("Permission denied"));
    }

    #[test]
    fn test_html_report_generation() {
        let generator = ReportGenerator::new();
        let result = create_test_analysis_result();

        let html_report = generator.generate_html(&result).unwrap();
        
        // Verify HTML structure
        assert!(html_report.contains("<!DOCTYPE html>"));
        assert!(html_report.contains("<title>Duplicate File Analysis Report</title>"));
        assert!(html_report.contains("Total files analyzed"));
        assert!(html_report.contains("/test/file1.txt"));
        assert!(html_report.contains("abc123def456"));
    }

    #[test]
    fn test_csv_report_generation() {
        let generator = ReportGenerator::new();
        let result = create_test_analysis_result();

        let csv_report = generator.generate_csv(&result).unwrap();
        
        // Verify CSV structure
        assert!(csv_report.contains("duplicate_set_id,file_path,file_size,potential_savings,hash,modified_time"));
        assert!(csv_report.contains("/test/file1.txt"));
        assert!(csv_report.contains("1024"));
        assert!(csv_report.contains("abc123def456"));
    }

    #[test]
    fn test_report_config_sorting() {
        let mut config = ReportConfig::default();
        config.sort_by_savings = true;
        
        let generator = ReportGenerator::with_config(config);
        let result = create_test_analysis_result();

        let text_report = generator.generate_text(&result).unwrap();
        
        // Should contain sorted content (our test has only one set, so this is basic)
        assert!(text_report.contains("sorted by potential savings"));
    }

    #[test]
    fn test_report_config_no_details() {
        let mut config = ReportConfig::default();
        config.include_details = false;
        
        let generator = ReportGenerator::with_config(config);
        let result = create_test_analysis_result();

        let json_report = generator.generate_json(&result).unwrap();
        
        // Should contain summary but not detailed file paths in simplified mode
        assert!(json_report.contains("summary"));
        assert!(json_report.contains("duplicate_sets"));
    }

    #[test]
    fn test_report_config_no_errors() {
        let mut config = ReportConfig::default();
        config.include_errors = false;
        
        let generator = ReportGenerator::with_config(config);
        let result = create_test_analysis_result();

        let text_report = generator.generate_text(&result).unwrap();
        
        // Should not contain error information
        assert!(!text_report.contains("Permission denied"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("test & <script>"), "test &amp; &lt;script&gt;");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("'single'"), "&#x27;single&#x27;");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("with,comma"), "\"with,comma\"");
        assert_eq!(csv_escape("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(csv_escape("with\nnewline"), "\"with\nnewline\"");
    }

    #[tokio::test]
    async fn test_save_to_file() {
        let generator = ReportGenerator::new();
        let content = "test content";
        
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_report.txt");
        
        generator.save_to_file(content, &file_path).await.unwrap();
        
        let saved_content = tokio::fs::read_to_string(&file_path).await.unwrap();
        assert_eq!(saved_content, content);
    }
}
