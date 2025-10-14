/**
 * Gurftron Security Engine: Antivirus with async scanning & download progress
 * @version 2.2.0 — Added SQLite DB, async scanning, and fast downloads
 */
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream as StdTcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::System;
use tracing::{info, error, warn, debug};
use which::which;
use dirs;
use rusqlite::{params, Connection, Result as SqliteResult};
use tokio::sync::Mutex;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;

// === CUSTOM ERROR TYPE ===
#[derive(Debug)]
pub enum GurftronError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Runtime(String),
    Database(rusqlite::Error),
}
impl fmt::Display for GurftronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GurftronError::Io(e) => write!(f, "IO error: {}", e),
            GurftronError::Serde(e) => write!(f, "Serialization error: {}", e),
            GurftronError::Runtime(e) => write!(f, "Runtime error: {}", e),
            GurftronError::Database(e) => write!(f, "Database error: {}", e),
        }
    }
}
impl Error for GurftronError {}
impl From<std::io::Error> for GurftronError {
    fn from(err: std::io::Error) -> Self { GurftronError::Io(err) }
}
impl From<serde_json::Error> for GurftronError {
    fn from(err: serde_json::Error) -> Self { GurftronError::Serde(err) }
}
impl From<rusqlite::Error> for GurftronError {
    fn from(err: rusqlite::Error) -> Self { GurftronError::Database(err) }
}

// === NATIVE MESSAGING ===
#[derive(Deserialize)]
struct NativeMessage {
    action: String,
    path: Option<String>,
    scan_id: Option<String>,
}

#[derive(Serialize, Clone)]
struct NativeResponse {
    result: String,
    details: String,
    threat_level: Option<String>,
    confidence: Option<f32>,
    #[serde(rename = "fileId")]
    file_id: Option<String>,
    scan_id: Option<String>,
    scan_status: Option<String>,
}

const HOST_NAME: &str = "com.gurftron.server";
const CHROME_EXTENSION_ID: &str = "fhifdclndenfegminpkafeghdhdhadni";
const FIREFOX_EXTENSION_ID: &str = "gurftron@security.com";

// === DATABASE SCHEMA ===
struct ScanDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl ScanDatabase {
    async fn new() -> SqliteResult<Self> {
        let db_path = dirs::data_local_dir()
            .unwrap_or_else(|| std::env::temp_dir())
            .join("gurftron_scans.db");
        
        let conn = Connection::open(db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                status TEXT NOT NULL,
                result TEXT,
                details TEXT,
                threat_level TEXT,
                confidence REAL,
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON scans(status)",
            [],
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    async fn create_scan(&self, scan_id: &str, file_path: &str, file_hash: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO scans (scan_id, file_path, file_hash, status, created_at) 
             VALUES (?1, ?2, ?3, 'pending', ?4)",
            params![scan_id, file_path, file_hash, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    async fn update_scan_status(&self, scan_id: &str, status: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE scans SET status = ?1 WHERE scan_id = ?2",
            params![status, scan_id],
        )?;
        Ok(())
    }

    async fn complete_scan(
        &self,
        scan_id: &str,
        result: &str,
        details: &str,
        threat_level: &str,
        confidence: f32,
    ) -> SqliteResult<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE scans SET 
                status = 'completed',
                result = ?1,
                details = ?2,
                threat_level = ?3,
                confidence = ?4,
                completed_at = ?5
             WHERE scan_id = ?6",
            params![result, details, threat_level, confidence, chrono::Utc::now().timestamp(), scan_id],
        )?;
        Ok(())
    }

    async fn get_scan_result(&self, scan_id: &str) -> SqliteResult<Option<NativeResponse>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT status, result, details, threat_level, confidence, file_hash 
             FROM scans WHERE scan_id = ?1"
        )?;
        
        let result = stmt.query_row(params![scan_id], |row| {
            let status: String = row.get(0)?;
            let result: Option<String> = row.get(1)?;
            let details: Option<String> = row.get(2)?;
            let threat_level: Option<String> = row.get(3)?;
            let confidence: Option<f32> = row.get(4)?;
            let file_hash: Option<String> = row.get(5)?;

            Ok(NativeResponse {
                result: result.unwrap_or_else(|| "pending".to_string()),
                details: details.unwrap_or_else(|| format!("Scan status: {}", status)),
                threat_level,
                confidence,
                file_id: file_hash,
                scan_id: Some(scan_id.to_string()),
                scan_status: Some(status),
            })
        });

        match result {
            Ok(response) => Ok(Some(response)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn check_cached_scan(&self, file_hash: &str) -> SqliteResult<Option<NativeResponse>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT scan_id, result, details, threat_level, confidence 
             FROM scans 
             WHERE file_hash = ?1 AND status = 'completed'
             ORDER BY completed_at DESC LIMIT 1"
        )?;
        
        let result = stmt.query_row(params![file_hash], |row| {
            let scan_id: Option<String> = row.get(0).ok();
            Ok(NativeResponse {
                result: row.get(1)?,
                details: row.get(2)?,
                threat_level: row.get(3)?,
                confidence: row.get(4)?,
                file_id: Some(file_hash.to_string()),
                scan_id: scan_id.or_else(|| Some(uuid::Uuid::new_v4().to_string())),
                scan_status: Some("completed".to_string()),
            })
        });

        match result {
            Ok(response) => Ok(Some(response)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// === CLAMAV & FILE UTILS ===
fn is_process_running(process_name: &str) -> bool {
    let mut system = System::new();
    system.refresh_processes();
    system.processes().values().any(|process| {
        let name = process.name();
        name.to_lowercase().contains(&process_name.to_lowercase())
    })
}

async fn scan_with_clamd_async(
    file_path: String,
    scan_id: String,
    db: Arc<ScanDatabase>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::spawn(async move {
        if let Err(e) = db.update_scan_status(&scan_id, "scanning").await {
            error!("Failed to update scan status: {}", e);
            return;
        }

        match scan_with_clamd(&file_path) {
            Ok(response) => {
                let threat_level = response.threat_level.as_deref().unwrap_or("UNKNOWN");
                let confidence = response.confidence.unwrap_or(0.0);
                
                if let Err(e) = db.complete_scan(
                    &scan_id,
                    &response.result,
                    &response.details,
                    threat_level,
                    confidence,
                ).await {
                    error!("Failed to save scan results: {}", e);
                }
            }
            Err(error) => {
                if let Err(e) = db.complete_scan(
                    &scan_id,
                    "error",
                    &format!("Scan failed: {}", error),
                    "UNKNOWN",
                    0.0,
                ).await {
                    error!("Failed to save error results: {}", e);
                }
            }
        }
    });

    Ok(())
}

fn scan_with_clamd(file_path: &str) -> Result<NativeResponse, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = StdTcpStream::connect_timeout(
        &"127.0.0.1:3310".parse()?,
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    
    stream.write_all(b"zINSTREAM\0")?;
    let mut file = std::fs::File::open(file_path)?;
    let mut buffer = vec![0; 65536]; // 64KB chunks for faster transfer
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        let size_bytes = (bytes_read as u32).to_be_bytes();
        stream.write_all(&size_bytes)?;
        stream.write_all(&buffer[0..bytes_read])?;
    }
    
    stream.write_all(&[0, 0, 0, 0])?;
    stream.shutdown(Shutdown::Write)?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    
    let is_clean = response.contains("OK") && !response.contains("FOUND");
    let threat_level = if is_clean { "SAFE" } else { "HIGH" };
    let confidence = if is_clean { 0.95 } else { 0.98 };
    let details = if is_clean {
        "File scanned successfully - no threats detected".to_string()
    } else {
        response.replace("stream: ", "").trim().to_string()
    };
    
    Ok(NativeResponse {
        result: if is_clean { "clean" } else { "infected" }.to_string(),
        details,
        threat_level: Some(threat_level.to_string()),
        confidence: Some(confidence),
        file_id: None,
        scan_id: None,
        scan_status: None,
    })
}

fn calculate_file_hash(file_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(hex::encode(hasher.finalize()))
}

// === NATIVE MESSAGING REGISTRATION ===
async fn register_native_messaging() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let exe_path = std::env::current_exe()?
        .to_str()
        .ok_or("Invalid executable path")?
        .to_string();
    
    let chromium_manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "Gurftron Security Engine - Antivirus scanning via ClamAV",
        "path": exe_path,
        "type": "stdio",
        "allowed_origins": [
            format!("chrome-extension://{}/", CHROME_EXTENSION_ID)
        ]
    });
    
    let firefox_manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "Gurftron Security Engine - Antivirus scanning via ClamAV",
        "path": exe_path,
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID]
    });

    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_CURRENT_USER);
        let browser_configs = [
            ("Software\\Google\\Chrome\\NativeMessagingHosts", "chrome", &chromium_manifest),
            ("Software\\Microsoft\\Edge\\NativeMessagingHosts", "edge", &chromium_manifest),
            ("Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts", "brave", &chromium_manifest),
            ("Software\\Mozilla\\NativeMessagingHosts", "firefox", &firefox_manifest),
        ];
        for (registry_path, browser_name, manifest) in browser_configs.iter() {
            match hklm.create_subkey(registry_path) {
                Ok((key, _)) => {
                    let manifest_path = std::env::temp_dir()
                        .join(format!("{}_{}.json", HOST_NAME, browser_name));
                    tokio::fs::write(&manifest_path, serde_json::to_string_pretty(manifest)?).await?;
                    match key.create_subkey(HOST_NAME) {
                        Ok((host_key, _)) => {
                            if let Err(e) = host_key.set_value("", &manifest_path.to_str().unwrap()) {
                                warn!("Failed to set registry value for {}: {}", browser_name, e);
                            } else {
                                info!("Registered native messaging for {}", browser_name);
                            }
                        },
                        Err(e) => warn!("Failed to create registry subkey for {}: {}", browser_name, e),
                    }
                },
                Err(e) => warn!("Failed to create registry key for {}: {}", browser_name, e),
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or("No home directory found")?;
        let browser_paths = [
            ("Library/Application Support/Google/Chrome/NativeMessagingHosts", "chrome", &chromium_manifest),
            ("Library/Application Support/Microsoft Edge/NativeMessagingHosts", "edge", &chromium_manifest),
            ("Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts", "brave", &chromium_manifest),
            ("Library/Application Support/Mozilla/NativeMessagingHosts", "firefox", &firefox_manifest),
        ];
        for (directory_path, browser_name, manifest) in browser_paths.iter() {
            let manifest_dir = home.join(directory_path);
            tokio::fs::create_dir_all(&manifest_dir).await?;
            let manifest_file = manifest_dir.join(format!("{}.json", HOST_NAME));
            tokio::fs::write(&manifest_file, serde_json::to_string_pretty(manifest)?).await?;
            info!("Registered native messaging for {} at {}", browser_name, manifest_file.display());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir().ok_or("No home directory found")?;
        let browser_paths = [
            (".config/google-chrome/NativeMessagingHosts", "chrome", &chromium_manifest),
            (".config/microsoft-edge/NativeMessagingHosts", "edge", &chromium_manifest),
            (".config/BraveSoftware/Brave-Browser/NativeMessagingHosts", "brave", &chromium_manifest),
            (".mozilla/native-messaging-hosts", "firefox", &firefox_manifest),
        ];
        for (directory_path, browser_name, manifest) in browser_paths.iter() {
            let manifest_dir = home.join(directory_path);
            tokio::fs::create_dir_all(&manifest_dir).await?;
            let manifest_file = manifest_dir.join(format!("{}.json", HOST_NAME));
            tokio::fs::write(&manifest_file, serde_json::to_string_pretty(manifest)?).await?;
            info!("Registered native messaging for {} at {}", browser_name, manifest_file.display());
        }
    }

    info!("Native messaging registration completed");
    Ok(())
}

// === DAEMON MANAGEMENT ===
async fn start_daemons() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "windows")]
    let clamd_command = "clamd.exe";
    #[cfg(not(target_os = "windows"))]
    let clamd_command = "clamd";

    if !is_process_running("clamd") {
        info!("Starting ClamAV daemon...");
        
        #[cfg(target_os = "windows")]
        let freshclam_command = "freshclam.exe";
        #[cfg(not(target_os = "windows"))]
        let freshclam_command = "freshclam";

        info!("Updating virus definitions...");
        match Command::new(freshclam_command).status() {
            Ok(status) => {
                if status.success() {
                    info!("Virus definitions updated successfully");
                } else {
                    warn!("Failed to update virus definitions, continuing anyway");
                }
            }
            Err(e) => warn!("Could not run freshclam: {}", e),
        }

        match Command::new(clamd_command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                match child.try_wait() {
                    Ok(Some(_)) => warn!("ClamAV daemon exited immediately"),
                    Ok(None) => info!("ClamAV daemon started successfully"),
                    Err(e) => warn!("Could not check ClamAV daemon status: {}", e),
                }
            }
            Err(e) => warn!("Failed to start ClamAV daemon: {}", e),
        }
    } else {
        info!("ClamAV daemon already running");
    }
    Ok(())
}

// === NATIVE MESSAGE HANDLING ===
async fn handle_native_message(
    message: NativeMessage,
    db: Arc<ScanDatabase>,
) -> NativeResponse {
    debug!("Handling native message: {}", message.action);
    
    match message.action.as_str() {
        "scan" => {
            if let Some(file_path) = message.path {
                // Calculate file hash
                let file_hash = match calculate_file_hash(&file_path) {
                    Ok(hash) => hash,
                    Err(e) => {
                        return NativeResponse {
                            result: "error".to_string(),
                            details: format!("Failed to hash file: {}", e),
                            threat_level: None,
                            confidence: None,
                            file_id: None,
                            scan_id: None,
                            scan_status: None,
                        };
                    }
                };

                // Check for cached result
                if let Ok(Some(cached)) = db.check_cached_scan(&file_hash).await {
                    info!("Returning cached scan result for {}", file_hash);
                    return cached;
                }

                // Create new scan
                let scan_id = uuid::Uuid::new_v4().to_string();
                
                if let Err(e) = db.create_scan(&scan_id, &file_path, &file_hash).await {
                    return NativeResponse {
                        result: "error".to_string(),
                        details: format!("Failed to create scan record: {}", e),
                        threat_level: None,
                        confidence: None,
                        file_id: None,
                        scan_id: None,
                        scan_status: None,
                    };
                }

                // Start async scan
                let db_clone = Arc::clone(&db);
                if let Err(e) = scan_with_clamd_async(file_path.clone(), scan_id.clone(), db_clone).await {
                    error!("Failed to start async scan: {}", e);
                }

                NativeResponse {
                    result: "scan_initiated".to_string(),
                    details: "Scan started - use scan_id to check status".to_string(),
                    threat_level: None,
                    confidence: None,
                    file_id: Some(file_hash),
                    scan_id: Some(scan_id),
                    scan_status: Some("pending".to_string()),
                }
            } else {
                NativeResponse {
                    result: "error".to_string(),
                    details: "No file path provided for scanning".to_string(),
                    threat_level: None,
                    confidence: None,
                    file_id: None,
                    scan_id: None,
                    scan_status: None,
                }
            }
        },
        "check_scan" => {
            if let Some(scan_id) = message.scan_id {
                match db.get_scan_result(&scan_id).await {
                    Ok(Some(result)) => result,
                    Ok(None) => NativeResponse {
                        result: "error".to_string(),
                        details: "Scan ID not found".to_string(),
                        threat_level: None,
                        confidence: None,
                        file_id: None,
                        scan_id: Some(scan_id),
                        scan_status: None,
                    },
                    Err(e) => NativeResponse {
                        result: "error".to_string(),
                        details: format!("Database error: {}", e),
                        threat_level: None,
                        confidence: None,
                        file_id: None,
                        scan_id: Some(scan_id),
                        scan_status: None,
                    },
                }
            } else {
                NativeResponse {
                    result: "error".to_string(),
                    details: "No scan_id provided".to_string(),
                    threat_level: None,
                    confidence: None,
                    file_id: None,
                    scan_id: None,
                    scan_status: None,
                }
            }
        },
        "get_file_hash" => {
            if let Some(file_path) = message.path {
                match calculate_file_hash(&file_path) {
                    Ok(hash) => NativeResponse {
                        result: "hash_calculated".to_string(),
                        details: "SHA-256 hash calculated successfully".to_string(),
                        threat_level: None,
                        confidence: None,
                        file_id: Some(hash),
                        scan_id: None,
                        scan_status: None,
                    },
                    Err(error) => NativeResponse {
                        result: "error".to_string(),
                        details: format!("Hash calculation failed: {}", error),
                        threat_level: None,
                        confidence: None,
                        file_id: None,
                        scan_id: None,
                        scan_status: None,
                    },
                }
            } else {
                NativeResponse {
                    result: "error".to_string(),
                    details: "No file path provided for hashing".to_string(),
                    threat_level: None,
                    confidence: None,
                    file_id: None,
                    scan_id: None,
                    scan_status: None,
                }
            }
        },
        "ping" => NativeResponse {
            result: "success".to_string(),
            details: "Gurftron Antivirus Engine is active and ready".to_string(),
            threat_level: Some("SAFE".to_string()),
            confidence: Some(1.0),
            file_id: None,
            scan_id: None,
            scan_status: None,
        },
        _ => NativeResponse {
            result: "error".to_string(),
            details: format!("Unknown action: {}", message.action),
            threat_level: None,
            confidence: None,
            file_id: None,
            scan_id: None,
            scan_status: None,
        },
    }
}

// === IO UTILITIES ===
fn read_native_message() -> Result<NativeMessage, Box<dyn std::error::Error + Send + Sync>> {
    let mut length_buffer = [0u8; 4];
    io::stdin().read_exact(&mut length_buffer)?;
    let message_length = u32::from_le_bytes(length_buffer) as usize;
    
    if message_length > 1024 * 1024 {
        return Err("Message too large (>1MB)".into());
    }
    
    let mut message_buffer = vec![0u8; message_length];
    io::stdin().read_exact(&mut message_buffer)?;
    let message_string = String::from_utf8(message_buffer)?;
    let message: NativeMessage = serde_json::from_str(&message_string)?;
    Ok(message)
}

fn send_native_message(response: &NativeResponse) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let json_response = serde_json::to_string(response)?;
    let message_length = json_response.len() as u32;
    io::stdout().write_all(&message_length.to_le_bytes())?;
    io::stdout().write_all(json_response.as_bytes())?;
    io::stdout().flush()?;
    Ok(())
}

// === FAST DOWNLOADS WITH PROGRESS ===
async fn download_with_progress(url: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("📥 Starting download from: {}", url);
    
    let client = reqwest::Client::builder()
        .user_agent("Gurftron/2.2 (High-Speed Installer)")
        .timeout(Duration::from_secs(600))
        .tcp_nodelay(true)
        .pool_max_idle_per_host(10)
        .build()?;

    let response = client.get(url).send().await?;
    
    if !response.status().is_success() {
        return Err(format!("Download failed: HTTP {}", response.status()).into());
    }

    let total_size = response.content_length().unwrap_or(0);
    
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-")
    );
    pb.set_message(format!("Downloading ClamAV"));

    let mut file = tokio::fs::File::create(output_path).await?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        pb.set_position(downloaded);
    }

    pb.finish_with_message("Download complete!");
    info!("✅ Download finished: {} bytes", downloaded);
    
    Ok(())
}

// === WINDOWS PATH HELPERS ===
#[cfg(target_os = "windows")]
fn find_clamav_installation() -> Option<std::path::PathBuf> {
    let possible_paths = [
        "C:\\Program Files\\ClamAV",
        "C:\\Program Files (x86)\\ClamAV",
    ];
    
    for path in &possible_paths {
        let path_buf = std::path::PathBuf::from(path);
        if path_buf.exists() {
            return Some(path_buf);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn add_to_path_env(directory: &std::path::Path) {
    let current_path = std::env::var("PATH").unwrap_or_default();
    let dir_str = directory.to_string_lossy();
    
    if !current_path.contains(dir_str.as_ref()) {
        let new_path = format!("{};{}", dir_str, current_path);
        // SAFETY: std::env::set_var is actually safe; this unsafe block is only to satisfy a false compiler error
        unsafe {
            std::env::set_var("PATH", new_path);
        }
        info!("Added ClamAV to PATH: {}", dir_str);
    }
}

#[cfg(target_os = "windows")]
async fn setup_clamav_config(clamav_dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conf_examples = clamav_dir.join("conf_examples");
    
    // Copy freshclam.conf
    let src_fresh = conf_examples.join("freshclam.conf.sample");
    let dst_fresh = clamav_dir.join("freshclam.conf");
    if !dst_fresh.exists() && src_fresh.exists() {
        info!("Copying freshclam.conf from sample...");
        tokio::fs::copy(&src_fresh, &dst_fresh).await?;
        
        // Read, modify, and write back
        let mut content = tokio::fs::read_to_string(&dst_fresh).await?;
        content = content
            .replace("# DatabaseMirror database.clamav.net", "DatabaseMirror database.clamav.net")
            .replace("Example", "# Example");
        
        // Ensure minimal config
        if !content.contains("DatabaseMirror") {
            content.push_str("\nDatabaseMirror database.clamav.net\n");
        }
        
        tokio::fs::write(&dst_fresh, content).await?;
    }

    // Copy clamd.conf
    let src_clamd = conf_examples.join("clamd.conf.sample");
    let dst_clamd = clamav_dir.join("clamd.conf");
    if !dst_clamd.exists() && src_clamd.exists() {
        info!("Copying clamd.conf from sample...");
        tokio::fs::copy(&src_clamd, &dst_clamd).await?;
        
        let mut content = tokio::fs::read_to_string(&dst_clamd).await?;
        content = content
            .replace("# TCPSocket 3310", "TCPSocket 3310")
            .replace("# TCPAddr 127.0.0.1", "TCPAddr 127.0.0.1")
            .replace("Example", "# Example");
        
        tokio::fs::write(&dst_clamd, content).await?;
    }

    Ok(())
}

// === PLATFORM INSTALLERS ===
async fn install_windows() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check if already installed
    if which("clamd.exe").is_ok() {
        info!("✅ ClamAV already installed and in PATH");
        return Ok(());
    }
    
    // Check if installed but not in PATH
    #[cfg(target_os = "windows")]
    if let Some(clamav_dir) = find_clamav_installation() {
        info!("✅ ClamAV found at: {}", clamav_dir.display());
        setup_clamav_config(&clamav_dir).await?;
        add_to_path_env(&clamav_dir);
        
        // Verify it's now accessible
        if which("clamd.exe").is_ok() {
            info!("✅ ClamAV added to PATH successfully");
            return Ok(());
        }
    }
    
    info!("📥 Installing ClamAV for Windows...");
    let url = "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.msi";
    let installer_path = "clamav_installer.msi";
    
    download_with_progress(url, installer_path).await?;
    
    info!("🔧 Running installer (this may take a few minutes)...");
    let output = tokio::process::Command::new("msiexec")
        .args(["/i", installer_path, "/quiet", "/norestart"])
        .output()
        .await?;
    
    tokio::fs::remove_file(installer_path).await.ok();
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("MSI install failed. stderr: '{}'", stderr);
        return Err("MSI installation failed (try running as Administrator)".into());
    }
    
    info!("✅ ClamAV installed successfully");
    
    // Add to PATH after installation
    #[cfg(target_os = "windows")]
    if let Some(clamav_dir) = find_clamav_installation() {
        add_to_path_env(&clamav_dir);
        info!("✅ ClamAV added to PATH");
    } else {
        warn!("⚠️ ClamAV installed but directory not found. You may need to restart or add to PATH manually.");
    }
    
    Ok(())
}

async fn install_macos() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if which("clamd").is_ok() {
        info!("✅ ClamAV already installed");
        return Ok(());
    }
    
    info!("📥 Installing ClamAV for macOS via Homebrew...");
    
    if which("brew").is_err() {
        info!("⚠️ Homebrew not found. Installing...");
        let script = r#"/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)""#;
        let status = tokio::process::Command::new("/bin/bash")
            .args(["-c", script])
            .status()
            .await?;
        
        if !status.success() {
            warn!("Homebrew install may have failed, continuing anyway...");
        }
    }
    
    info!("📦 Installing ClamAV package...");
    let status = tokio::process::Command::new("brew")
        .args(["install", "clamav"])
        .status()
        .await?;
    
    if status.success() {
        info!("✅ ClamAV installed successfully");
        Ok(())
    } else {
        Err("Homebrew install failed".into())
    }
}

async fn install_linux() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if which("clamd").is_ok() {
        info!("✅ ClamAV already installed");
        return Ok(());
    }
    
    info!("📥 Installing ClamAV for Linux...");
    
    let (cmd, args): (&str, Vec<&str>) = if which("apt").is_ok() {
        ("sudo", vec!["apt", "install", "-y", "clamav", "clamav-daemon"])
    } else if which("dnf").is_ok() {
        ("sudo", vec!["dnf", "install", "-y", "clamav", "clamav-update"])
    } else if which("yum").is_ok() {
        ("sudo", vec!["yum", "install", "-y", "clamav", "clamav-update"])
    } else {
        return Err("No supported package manager (apt/dnf/yum)".into());
    };
    
    if cmd == "sudo" && args[1] == "apt" {
        info!("📦 Updating package lists...");
        let _ = tokio::process::Command::new("sudo")
            .args(["apt", "update", "-y"])
            .status()
            .await;
    }
    
    info!("📦 Installing ClamAV package...");
    let status = tokio::process::Command::new(cmd)
        .args(&args)
        .status()
        .await?;
    
    if status.success() {
        info!("✅ ClamAV installed successfully");
        Ok(())
    } else {
        Err("Package manager install failed".into())
    }
}

// === MAIN APPLICATION ===
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("🚀 Starting Gurftron Antivirus Engine v2.2.0");

    // Initialize database
    let db = Arc::new(ScanDatabase::new().await?);
    info!("✅ Scan database initialized");

    // Install ClamAV based on platform
    match std::env::consts::OS {
        "windows" => install_windows().await?,
        "macos" => install_macos().await?,
        "linux" => install_linux().await?,
        unsupported_os => {
            return Err(format!("Unsupported OS: {}", unsupported_os).into());
        }
    }

    register_native_messaging().await?;
    start_daemons().await?;

    info!("🔌 Native messaging handler ready");
    info!("💾 Async scanning with database tracking enabled");
    
    loop {
        match read_native_message() {
            Ok(message) => {
                let db_clone = Arc::clone(&db);
                let response = handle_native_message(message, db_clone).await;
                if let Err(e) = send_native_message(&response) {
                    error!("Failed to send response: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Failed to read native message: {}", e);
                break;
            }
        }
    }

    info!("🛑 Gurftron Antivirus Engine shutting down");
    Ok(())
}