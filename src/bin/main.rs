//! CLI entry point for the duplicate file analyzer

use clap::{Parser, Subcommand, ValueEnum};
use duplicate_file_analyzer::{Config, HashAlgorithm, Result, DiscoveryOptions, AnalysisController};
use duplicate_file_analyzer::report::{ReportGenerator, OutputFormat as ReportOutputFormat};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber;
use anyhow;

#[derive(Parser)]
#[command(name = "duplicate-analyzer")]
#[command(about = "A high-performance tool for identifying duplicate files")]
#[command(version = "0.1.0")]
#[command(long_about = "A high-performance tool for identifying duplicate files across large directory structures. Supports multiple output formats, hash algorithms, and parallel processing.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a directory for duplicate files
    Analyze {
        /// Target directory to analyze
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Hash algorithm to use
        #[arg(long, value_enum, default_value_t = HashAlgorithmArg::Sha256)]
        hash: HashAlgorithmArg,

        /// Number of threads to use (default: number of CPU cores)
        #[arg(short, long)]
        threads: Option<usize>,

        /// Exclude patterns (glob patterns, can be specified multiple times)
        #[arg(short, long, value_name = "PATTERN")]
        exclude: Vec<String>,

        /// Exclude directories (can be specified multiple times)
        #[arg(long, value_name = "DIRECTORY")]
        exclude_dir: Vec<String>,

        /// Include only these file extensions (can be specified multiple times)
        #[arg(long, value_name = "EXT")]
        include_ext: Vec<String>,

        /// Exclude these file extensions (can be specified multiple times)
        #[arg(long, value_name = "EXT")]
        exclude_ext: Vec<String>,

        /// Output file path (if not specified, output goes to stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Minimum file size to consider (in bytes)
        #[arg(long, value_name = "BYTES")]
        min_size: Option<u64>,

        /// Maximum file size to consider (in bytes)
        #[arg(long, value_name = "BYTES")]
        max_size: Option<u64>,

        /// Follow symbolic links
        #[arg(long)]
        follow_links: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Resume from previous analysis (if available)
        #[arg(long)]
        resume: bool,
    },

    /// Start the web server
    Web {
        /// Port to bind to
        #[arg(short, long, default_value = "3000")]
        port: u16,

        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    /// Human-readable text format
    Text,
    /// JSON format for programmatic use
    Json,
    /// HTML format for web viewing
    Html,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HashAlgorithmArg {
    /// SHA-256 (recommended for security)
    Sha256,
    /// MD5 (faster but less secure)
    Md5,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            directory,
            format,
            hash,
            threads,
            exclude,
            exclude_dir,
            include_ext,
            exclude_ext,
            output,
            min_size,
            max_size,
            follow_links,
            verbose,
            resume,
        } => {
            // Initialize tracing with appropriate level
            let level = if verbose { Level::DEBUG } else { Level::INFO };
            tracing_subscriber::fmt().with_max_level(level).init();

            info!("Starting analysis of directory: {:?}", directory);

            // Validate directory exists
            if !directory.exists() {
                eprintln!("Error: Directory does not exist: {:?}", directory);
                std::process::exit(1);
            }

            if !directory.is_dir() {
                eprintln!("Error: Path is not a directory: {:?}", directory);
                std::process::exit(1);
            }

            // Convert hash algorithm
            let hash_algorithm = match hash {
                HashAlgorithmArg::Sha256 => HashAlgorithm::Sha256,
                HashAlgorithmArg::Md5 => HashAlgorithm::Md5,
            };

            // Create configuration
            let mut config = Config::default();
            config.hash_algorithm = hash_algorithm;
            if let Some(thread_count) = threads {
                if thread_count == 0 {
                    eprintln!("Error: Thread count must be greater than 0");
                    std::process::exit(1);
                }
                config.thread_count = thread_count;
            }

            // Validate size constraints
            if let (Some(min), Some(max)) = (min_size, max_size) {
                if min > max {
                    eprintln!("Error: Minimum size cannot be greater than maximum size");
                    std::process::exit(1);
                }
            }

            // Create discovery options
            let mut discovery_options = DiscoveryOptions::default()
                .exclude_patterns(exclude)
                .exclude_directories(exclude_dir)
                .include_extensions(include_ext)
                .exclude_extensions(exclude_ext)
                .follow_symlinks(follow_links);

            // Set size filters if specified
            if let Some(min) = min_size {
                discovery_options = discovery_options.min_file_size(min);
            }
            if let Some(max) = max_size {
                discovery_options = discovery_options.max_file_size(max);
            }

            // Create analysis controller with resume capability if requested
            let mut controller = if resume {
                match AnalysisController::with_resume() {
                    Ok(controller) => {
                        println!("Resume functionality enabled");
                        controller
                    }
                    Err(err) => {
                        eprintln!("Warning: Could not enable resume functionality: {}", err);
                        println!("Continuing without resume capability");
                        AnalysisController::new()
                    }
                }
            } else {
                AnalysisController::new()
            };
            
            // Set up signal handling for graceful interruption
            let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            let tx_clone = tx.clone();
            
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
                println!("\nReceived interrupt signal, stopping analysis...");
                let _ = tx_clone.send(()).await;
            });

            // Start analysis
            println!("Starting analysis of directory: {:?}", directory);
            println!("Configuration:");
            println!("  Hash algorithm: {}", hash_algorithm);
            println!("  Threads: {}", config.thread_count);
            println!("  Follow symlinks: {}", discovery_options.follow_symlinks);
            if !discovery_options.exclude_patterns.is_empty() {
                println!("  Exclude patterns: {:?}", discovery_options.exclude_patterns);
            }
            if !discovery_options.exclude_directories.is_empty() {
                println!("  Exclude directories: {:?}", discovery_options.exclude_directories);
            }
            if !discovery_options.include_extensions.is_empty() {
                println!("  Include extensions: {:?}", discovery_options.include_extensions);
            }
            if !discovery_options.exclude_extensions.is_empty() {
                println!("  Exclude extensions: {:?}", discovery_options.exclude_extensions);
            }
            if let Some(min) = discovery_options.min_file_size {
                println!("  Minimum file size: {} bytes", min);
            }
            if let Some(max) = discovery_options.max_file_size {
                println!("  Maximum file size: {} bytes", max);
            }
            println!();

            // Run analysis with interruption handling
            let analysis_result = tokio::select! {
                result = run_analysis_with_resume(&mut controller, &directory, discovery_options, config, resume) => {
                    match result {
                        Ok(analysis_result) => {
                            println!("Analysis completed successfully!");
                            analysis_result
                        }
                        Err(err) => {
                            eprintln!("Analysis failed: {}", err);
                            std::process::exit(1);
                        }
                    }
                }
                _ = rx.recv() => {
                    println!("Analysis interrupted by user");
                    // Try to get partial results
                    match controller.cancel_analysis().await {
                        Ok(_) => println!("Analysis cancelled gracefully"),
                        Err(err) => eprintln!("Error during cancellation: {}", err),
                    }
                    // For now, exit - in a full implementation we'd return partial results
                    std::process::exit(130); // Standard exit code for SIGINT
                }
            };

            // Generate and output report
            let report_generator = ReportGenerator::new();
            let report_format: ReportOutputFormat = format.into();
            let report_content = report_generator.generate_report(&analysis_result, report_format)?;

            // Output report
            match output {
                Some(output_path) => {
                    report_generator.save_to_file(&report_content, &output_path).await?;
                    println!("Report saved to: {:?}", output_path);
                }
                None => {
                    println!("{}", report_content);
                }
            }
        }

        Commands::Web { port, host, verbose } => {
            // Initialize tracing with appropriate level
            let level = if verbose { Level::DEBUG } else { Level::INFO };
            tracing_subscriber::fmt().with_max_level(level).init();

            info!("Starting web server on {}:{}", host, port);

            // Import web server components
            use duplicate_file_analyzer::web::api::{WebAPIServer, AnalysisRequest};
            use axum::{
                routing::{get, post},
                Router,
                extract::{Path, Json},
                response::Json as ResponseJson,
                http::StatusCode,
            };
            use tower::ServiceBuilder;
            use tower_http::{
                cors::CorsLayer,
                services::ServeDir,
            };
            use std::net::SocketAddr;

            // Create the web API server
            let api_server = std::sync::Arc::new(WebAPIServer::new());

            // Create the main router
            let app = Router::new()
                // Serve static files from web/static directory
                .nest_service("/", ServeDir::new("web/static"))
                // API routes
                .route("/api/analysis", post({
                    let server = api_server.clone();
                    move |Json(request): Json<AnalysisRequest>| async move {
                        match server.start_analysis(request).await {
                            Ok(session) => Ok(ResponseJson(session)),
                            Err(err) => {
                                eprintln!("Failed to start analysis: {}", err);
                                Err(StatusCode::INTERNAL_SERVER_ERROR)
                            }
                        }
                    }
                }))
                .route("/api/analysis/:id", get({
                    let server = api_server.clone();
                    move |Path(session_id): Path<String>| async move {
                        match server.get_analysis_status(&session_id).await {
                            Ok(Some(status)) => Ok(ResponseJson(status)),
                            Ok(None) => Err(StatusCode::NOT_FOUND),
                            Err(err) => {
                                eprintln!("Failed to get status: {}", err);
                                Err(StatusCode::INTERNAL_SERVER_ERROR)
                            }
                        }
                    }
                }))
                .route("/api/analysis/:id/results", get({
                    let server = api_server.clone();
                    move |Path(session_id): Path<String>| async move {
                        match server.get_analysis_results(&session_id).await {
                            Ok(Some(results)) => Ok(ResponseJson(results)),
                            Ok(None) => Err(StatusCode::NOT_FOUND),
                            Err(err) => {
                                eprintln!("Failed to get results: {}", err);
                                Err(StatusCode::INTERNAL_SERVER_ERROR)
                            }
                        }
                    }
                }))
                // File operations
                .route("/api/files/delete", post({
                    let server = api_server.clone();
                    move |Json(request): Json<serde_json::Value>| async move {
                        if let Some(file_path) = request.get("file_path").and_then(|v| v.as_str()) {
                            match server.delete_file(file_path).await {
                                Ok(true) => Ok(ResponseJson(serde_json::json!({"success": true}))),
                                Ok(false) => Ok(ResponseJson(serde_json::json!({"success": false, "error": "File not found"}))),
                                Err(err) => {
                                    eprintln!("Failed to delete file: {}", err);
                                    Ok(ResponseJson(serde_json::json!({"success": false, "error": "Failed to delete file"})))
                                }
                            }
                        } else {
                            Err(StatusCode::BAD_REQUEST)
                        }
                    }
                }))
                .route("/api/files/batch", post({
                    let server = api_server.clone();
                    move |Json(request): Json<serde_json::Value>| async move {
                        if let Some(file_paths) = request.get("file_paths").and_then(|v| v.as_array()) {
                            let paths: Vec<String> = file_paths
                                .iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect();
                            
                            match server.delete_files(&paths).await {
                                Ok(results) => Ok(ResponseJson(serde_json::json!({"results": results}))),
                                Err(err) => {
                                    eprintln!("Failed to delete files: {}", err);
                                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                                }
                            }
                        } else {
                            Err(StatusCode::BAD_REQUEST)
                        }
                    }
                }))
                .layer(
                    ServiceBuilder::new()
                        .layer(CorsLayer::permissive())
                );

            // Parse the socket address
            let addr: SocketAddr = format!("{}:{}", host, port).parse()
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            println!("🚀 Web server starting on http://{}", addr);
            println!("📁 Serving static files from: web/static/");
            println!("🔗 Open http://{}/ in your browser to access the web interface", addr);

            // Start the server
            let listener = tokio::net::TcpListener::bind(addr).await
                .map_err(|e| anyhow::anyhow!("Failed to bind to address {}: {}", addr, e))?;

            axum::serve(listener, app).await
                .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;
        }
    }

    Ok(())
}

/// Convert CLI OutputFormat to ReportOutputFormat
impl From<OutputFormat> for ReportOutputFormat {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Text => ReportOutputFormat::Text,
            OutputFormat::Json => ReportOutputFormat::Json,
            OutputFormat::Html => ReportOutputFormat::Html,
        }
    }
}

/// Run the analysis workflow with optional resume
async fn run_analysis_with_resume(
    controller: &mut AnalysisController,
    directory: &std::path::PathBuf,
    discovery_options: DiscoveryOptions,
    _config: Config,
    resume: bool,
) -> Result<duplicate_file_analyzer::AnalysisResult> {
    use std::time::Instant;
    
    let start_time = Instant::now();
    
    // If resume is requested, try to find existing sessions
    let resume_session_id = if resume {
        let sessions = controller.list_resumable_sessions().await?;
        if !sessions.is_empty() {
            println!("Found {} resumable session(s):", sessions.len());
            for session in &sessions {
                println!("  - {}", session);
            }
            
            // For simplicity, use the first available session
            // In a full implementation, we'd let the user choose
            Some(sessions[0].clone())
        } else {
            println!("No resumable sessions found, starting new analysis");
            None
        }
    } else {
        None
    };
    
    // Run the analysis
    let mut result = controller.analyze_directory_with_resume(directory, discovery_options, resume_session_id).await?;
    
    // Set the analysis time
    result.analysis_time = start_time.elapsed().as_secs_f64();
    
    Ok(result)
}
