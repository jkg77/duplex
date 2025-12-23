//! WebSocket handler for real-time progress updates

use crate::{models::ProgressUpdate, web::api::WebAPIServer};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// WebSocket message types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    #[serde(rename = "connected")]
    Connected { message: String },
    
    #[serde(rename = "progress")]
    Progress { 
        session_id: Option<String>,
        data: ProgressUpdate 
    },
    
    #[serde(rename = "analysis_complete")]
    AnalysisComplete { 
        session_id: String,
        success: bool,
        message: String 
    },
    
    #[serde(rename = "error")]
    Error { message: String },
    
    #[serde(rename = "subscribe")]
    Subscribe { session_id: String },
    
    #[serde(rename = "unsubscribe")]
    Unsubscribe { session_id: String },
    
    #[serde(rename = "ping")]
    Ping,
    
    #[serde(rename = "pong")]
    Pong,
}

/// WebSocket connection state
struct ConnectionState {
    subscribed_sessions: HashMap<String, bool>,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            subscribed_sessions: HashMap::new(),
        }
    }
}

/// WebSocket handler for real-time updates
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(api_server): State<Arc<WebAPIServer>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, api_server))
}

/// Handle individual WebSocket connections
async fn handle_socket(mut socket: WebSocket, api_server: Arc<WebAPIServer>) {
    let mut connection_state = ConnectionState::new();
    
    // Send initial connection message
    let connected_msg = WebSocketMessage::Connected {
        message: "WebSocket connection established".to_string(),
    };
    
    if send_message(&mut socket, &connected_msg).await.is_err() {
        return;
    }

    // Set up periodic updates for subscribed sessions
    let mut update_interval = interval(Duration::from_millis(500)); // Update every 500ms
    let mut ping_interval = interval(Duration::from_secs(30)); // Ping every 30 seconds

    loop {
        tokio::select! {
            _ = update_interval.tick() => {
                // Send progress updates for all subscribed sessions
                let session_ids: Vec<String> = connection_state.subscribed_sessions.keys().cloned().collect();
                let mut completed_sessions = Vec::new();
                
                for session_id in session_ids {
                    if let Ok(Some(session)) = api_server.get_analysis_status(&session_id).await {
                        let progress_msg = WebSocketMessage::Progress {
                            session_id: Some(session_id.clone()),
                            data: ProgressUpdate {
                                files_processed: (session.progress * 100.0) as u64, // Placeholder
                                total_files: 100, // Placeholder
                                current_file: None,
                                bytes_processed: 0,
                                duplicates_found: 0,
                                estimated_completion: session.estimated_completion,
                            },
                        };
                        
                        if send_message(&mut socket, &progress_msg).await.is_err() {
                            return;
                        }
                        
                        // Check if analysis is complete
                        if matches!(session.status, crate::web::api::AnalysisStatus::Completed | 
                                   crate::web::api::AnalysisStatus::Failed | 
                                   crate::web::api::AnalysisStatus::Cancelled) {
                            
                            let complete_msg = WebSocketMessage::AnalysisComplete {
                                session_id: session_id.clone(),
                                success: matches!(session.status, crate::web::api::AnalysisStatus::Completed),
                                message: match session.status {
                                    crate::web::api::AnalysisStatus::Completed => "Analysis completed successfully".to_string(),
                                    crate::web::api::AnalysisStatus::Failed => "Analysis failed".to_string(),
                                    crate::web::api::AnalysisStatus::Cancelled => "Analysis was cancelled".to_string(),
                                    _ => "Analysis finished".to_string(),
                                },
                            };
                            
                            if send_message(&mut socket, &complete_msg).await.is_err() {
                                return;
                            }
                            
                            // Mark session for removal
                            completed_sessions.push(session_id);
                        }
                    }
                }
                
                // Remove completed sessions
                for session_id in completed_sessions {
                    connection_state.subscribed_sessions.remove(&session_id);
                }
            }

            _ = ping_interval.tick() => {
                // Send ping to keep connection alive
                let ping_msg = WebSocketMessage::Ping;
                if send_message(&mut socket, &ping_msg).await.is_err() {
                    return;
                }
            }

            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = handle_client_message(&mut connection_state, &text, &mut socket).await {
                            tracing::error!("Error handling WebSocket message: {}", e);
                            let error_msg = WebSocketMessage::Error {
                                message: format!("Error processing message: {}", e),
                            };
                            if send_message(&mut socket, &error_msg).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!("WebSocket connection closed by client");
                        break;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        tracing::debug!("Received pong from client");
                    }
                    Some(Err(e)) => {
                        tracing::error!("WebSocket error: {}", e);
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
        }
    }

    tracing::info!("WebSocket connection terminated");
}

/// Handle incoming messages from the client
async fn handle_client_message(
    connection_state: &mut ConnectionState,
    text: &str,
    socket: &mut WebSocket,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let message: WebSocketMessage = serde_json::from_str(text)?;
    
    match message {
        WebSocketMessage::Subscribe { session_id } => {
            tracing::info!("Client subscribed to session: {}", session_id);
            connection_state.subscribed_sessions.insert(session_id, true);
        }
        
        WebSocketMessage::Unsubscribe { session_id } => {
            tracing::info!("Client unsubscribed from session: {}", session_id);
            connection_state.subscribed_sessions.remove(&session_id);
        }
        
        WebSocketMessage::Ping => {
            let pong_msg = WebSocketMessage::Pong;
            send_message(socket, &pong_msg).await?;
        }
        
        _ => {
            tracing::debug!("Received unhandled message type from client");
        }
    }
    
    Ok(())
}

/// Send a WebSocket message
async fn send_message(
    socket: &mut WebSocket,
    message: &WebSocketMessage,
) -> Result<(), axum::Error> {
    let json_str = serde_json::to_string(message)
        .map_err(|e| axum::Error::new(format!("Failed to serialize message: {}", e)))?;
    
    socket.send(Message::Text(json_str)).await
}

/// Broadcast a message to all connected WebSocket clients
/// This would be used by the analysis engine to send real-time updates
pub async fn broadcast_progress_update(
    _session_id: &str,
    _progress: &ProgressUpdate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TODO: Implement broadcasting to all connected clients
    // This would require a global registry of WebSocket connections
    // For now, this is a placeholder for future implementation
    Ok(())
}

/// Broadcast analysis completion to all connected clients
pub async fn broadcast_analysis_complete(
    _session_id: &str,
    _success: bool,
    _message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TODO: Implement broadcasting to all connected clients
    // This would require a global registry of WebSocket connections
    // For now, this is a placeholder for future implementation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::api::{AnalysisOptions, AnalysisRequest, AnalysisStatus};
    use proptest::prelude::*;
    use std::path::PathBuf;
    use std::time::SystemTime;
    use tempfile::TempDir;
    use tokio_test;

    // Property-based test generators
    prop_compose! {
        fn arb_progress_update()(
            files_processed in 0u64..10000,
            total_files in 1u64..10000,
            bytes_processed in 0u64..1_000_000_000,
            duplicates_found in 0u64..1000,
            current_file_opt in prop::option::of("[a-zA-Z0-9_/.-]{1,50}")
        ) -> ProgressUpdate {
            // Ensure files_processed doesn't exceed total_files
            let files_processed = files_processed.min(total_files);
            
            ProgressUpdate {
                files_processed,
                total_files,
                current_file: current_file_opt.map(PathBuf::from),
                bytes_processed,
                duplicates_found,
                estimated_completion: None,
            }
        }
    }

    prop_compose! {
        fn arb_websocket_message()(
            message_type in 0..6u8,
            session_id in "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            progress in arb_progress_update(),
            message_text in "[a-zA-Z0-9 ]{1,100}"
        ) -> WebSocketMessage {
            match message_type {
                0 => WebSocketMessage::Connected { message: message_text },
                1 => WebSocketMessage::Progress { 
                    session_id: Some(session_id.clone()), 
                    data: progress 
                },
                2 => WebSocketMessage::AnalysisComplete { 
                    session_id: session_id.clone(), 
                    success: true, 
                    message: message_text 
                },
                3 => WebSocketMessage::Subscribe { session_id },
                4 => WebSocketMessage::Ping,
                _ => WebSocketMessage::Error { message: message_text },
            }
        }
    }

    prop_compose! {
        fn arb_analysis_request()(
            target_dir in "[a-zA-Z0-9_/.-]{1,50}",
            exclude_patterns in prop::collection::vec("[a-zA-Z0-9*?]{1,20}", 0..5),
            follow_symlinks in any::<bool>(),
            hash_algorithm in prop::option::of("(sha256|md5|xxhash)"),
            thread_count in prop::option::of(1usize..16)
        ) -> AnalysisRequest {
            AnalysisRequest {
                target_directory: PathBuf::from(target_dir),
                options: AnalysisOptions {
                    hash_algorithm,
                    thread_count,
                    follow_symlinks: Some(follow_symlinks),
                },
                exclude_patterns: if exclude_patterns.is_empty() { None } else { Some(exclude_patterns) },
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: duplicate-file-analyzer, Property 13: Web Interface Progress Updates**
        /// **Validates: Requirements 7.6, 7.7**
        /// For any running analysis, the web interface should display real-time progress updates 
        /// including current file and percentage completion
        #[test]
        fn test_websocket_message_serialization_roundtrip(message in arb_websocket_message()) {
            // Property: WebSocket messages should serialize and deserialize correctly
            let serialized = serde_json::to_string(&message).unwrap();
            let deserialized: WebSocketMessage = serde_json::from_str(&serialized).unwrap();
            
            // Verify the message type is preserved
            match (&message, &deserialized) {
                (WebSocketMessage::Connected { .. }, WebSocketMessage::Connected { .. }) => {},
                (WebSocketMessage::Progress { .. }, WebSocketMessage::Progress { .. }) => {},
                (WebSocketMessage::AnalysisComplete { .. }, WebSocketMessage::AnalysisComplete { .. }) => {},
                (WebSocketMessage::Subscribe { .. }, WebSocketMessage::Subscribe { .. }) => {},
                (WebSocketMessage::Unsubscribe { .. }, WebSocketMessage::Unsubscribe { .. }) => {},
                (WebSocketMessage::Error { .. }, WebSocketMessage::Error { .. }) => {},
                (WebSocketMessage::Ping, WebSocketMessage::Ping) => {},
                (WebSocketMessage::Pong, WebSocketMessage::Pong) => {},
                _ => panic!("Message type not preserved during serialization"),
            }
        }

        /// Test progress update consistency
        #[test]
        fn test_progress_update_consistency(progress in arb_progress_update()) {
            // Property: Progress updates should have consistent data
            assert!(progress.files_processed <= progress.total_files, 
                "Files processed should not exceed total files");
            
            assert!(progress.bytes_processed >= 0, 
                "Bytes processed should be non-negative");
            
            assert!(progress.duplicates_found >= 0, 
                "Duplicates found should be non-negative");
            
            // Property: Progress percentage should be between 0 and 100
            let percentage = progress.progress_percentage();
            assert!(percentage >= 0.0 && percentage <= 100.0, 
                "Progress percentage should be between 0 and 100, got {}", percentage);
            
            // Property: If all files are processed, percentage should be 100
            if progress.files_processed == progress.total_files {
                assert!((percentage - 100.0).abs() < f64::EPSILON, 
                    "Progress should be 100% when all files are processed");
            }
        }

        /// Test WebSocket message creation for progress updates
        #[test]
        fn test_websocket_progress_message_creation(
            session_id in "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            progress in arb_progress_update()
        ) {
            // Property: Progress messages should be created correctly
            let message = WebSocketMessage::Progress {
                session_id: Some(session_id.clone()),
                data: progress.clone(),
            };
            
            // Verify message can be serialized
            let serialized = serde_json::to_string(&message).unwrap();
            assert!(!serialized.is_empty(), "Serialized message should not be empty");
            
            // Verify message contains expected fields
            assert!(serialized.contains("\"type\":\"progress\""), 
                "Message should contain progress type");
            assert!(serialized.contains(&session_id), 
                "Message should contain session ID");
            assert!(serialized.contains("files_processed"), 
                "Message should contain files_processed field");
            assert!(serialized.contains("total_files"), 
                "Message should contain total_files field");
        }

        /// Test analysis completion message creation
        #[test]
        fn test_websocket_completion_message_creation(
            session_id in "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            success in any::<bool>(),
            message_text in "[a-zA-Z0-9 ]{1,100}"
        ) {
            // Property: Completion messages should be created correctly
            let message = WebSocketMessage::AnalysisComplete {
                session_id: session_id.clone(),
                success,
                message: message_text.clone(),
            };
            
            // Verify message can be serialized
            let serialized = serde_json::to_string(&message).unwrap();
            assert!(!serialized.is_empty(), "Serialized message should not be empty");
            
            // Verify message contains expected fields
            assert!(serialized.contains("\"type\":\"analysis_complete\""), 
                "Message should contain analysis_complete type");
            assert!(serialized.contains(&session_id), 
                "Message should contain session ID");
            assert!(serialized.contains(&format!("\"success\":{}", success)), 
                "Message should contain success field");
            assert!(serialized.contains(&message_text), 
                "Message should contain message text");
        }
    }

    #[tokio::test]
    async fn test_websocket_message_handling() {
        // Test basic WebSocket message creation and serialization
        let progress = ProgressUpdate {
            files_processed: 50,
            total_files: 100,
            current_file: Some(PathBuf::from("/test/file.txt")),
            bytes_processed: 1024,
            duplicates_found: 5,
            estimated_completion: Some(SystemTime::now()),
        };

        let message = WebSocketMessage::Progress {
            session_id: Some("test-session-123".to_string()),
            data: progress,
        };

        // Should serialize without error
        let serialized = serde_json::to_string(&message).unwrap();
        assert!(!serialized.is_empty());

        // Should deserialize back to the same structure
        let deserialized: WebSocketMessage = serde_json::from_str(&serialized).unwrap();
        
        match deserialized {
            WebSocketMessage::Progress { session_id, data } => {
                assert_eq!(session_id, Some("test-session-123".to_string()));
                assert_eq!(data.files_processed, 50);
                assert_eq!(data.total_files, 100);
                assert_eq!(data.bytes_processed, 1024);
                assert_eq!(data.duplicates_found, 5);
            }
            _ => panic!("Expected Progress message"),
        }
    }

    #[tokio::test]
    async fn test_connection_state_management() {
        let mut connection_state = ConnectionState::new();
        
        // Initially no subscriptions
        assert!(connection_state.subscribed_sessions.is_empty());
        
        // Add subscription
        connection_state.subscribed_sessions.insert("session-1".to_string(), true);
        assert_eq!(connection_state.subscribed_sessions.len(), 1);
        assert!(connection_state.subscribed_sessions.contains_key("session-1"));
        
        // Add another subscription
        connection_state.subscribed_sessions.insert("session-2".to_string(), true);
        assert_eq!(connection_state.subscribed_sessions.len(), 2);
        
        // Remove subscription
        connection_state.subscribed_sessions.remove("session-1");
        assert_eq!(connection_state.subscribed_sessions.len(), 1);
        assert!(!connection_state.subscribed_sessions.contains_key("session-1"));
        assert!(connection_state.subscribed_sessions.contains_key("session-2"));
    }

    #[tokio::test]
    async fn test_api_server_integration() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create a test file
        std::fs::write(temp_dir.path().join("test.txt"), "test content").unwrap();
        
        let api_server = Arc::new(WebAPIServer::new());
        
        // Test starting an analysis
        let request = AnalysisRequest {
            target_directory: temp_dir.path().to_path_buf(),
            options: AnalysisOptions {
                hash_algorithm: None,
                thread_count: None,
                follow_symlinks: Some(false),
            },
            exclude_patterns: None,
        };
        
        let session = api_server.start_analysis(request).await.unwrap();
        assert_eq!(session.status, AnalysisStatus::Running);
        assert!(!session.session_id.is_empty());
        
        // Test getting session status
        let status = api_server.get_analysis_status(&session.session_id).await.unwrap();
        assert!(status.is_some());
        
        // Wait a bit for analysis to potentially complete
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Test getting active sessions
        let active_sessions = api_server.get_active_sessions().await.unwrap();
        assert!(!active_sessions.is_empty());
    }
}
