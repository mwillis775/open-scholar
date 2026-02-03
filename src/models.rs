//! Data models for Scholar

use chrono::{DateTime, Utc};
use rusqlite::Row;
use serde::{Deserialize, Serialize};

// ============================================================================
// User models
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub public_key: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub affiliation: Option<String>,
    pub avatar_hash: Option<String>,
    pub is_admin: bool,
    pub is_moderator: bool,
    pub is_verified: bool,
    pub email_verified: bool,
    pub total_uploads: i64,
    pub total_reviews: i64,
    pub reputation_score: i64,
    pub created_at: String,
    pub last_login: Option<String>,
    #[serde(skip)]
    pub role: String,
}

impl User {
    pub fn from_row(row: &Row) -> rusqlite::Result<Self> {
        let is_admin = row.get::<_, i64>("is_admin").unwrap_or(0) == 1;
        let is_moderator = row.get::<_, i64>("is_moderator").unwrap_or(0) == 1;
        
        let role = if is_admin {
            "admin".to_string()
        } else if is_moderator {
            "moderator".to_string()
        } else {
            "user".to_string()
        };
        
        Ok(Self {
            id: row.get("id")?,
            username: row.get("username")?,
            email: row.get("email").ok(),
            public_key: row.get("public_key")?,
            display_name: row.get("display_name").ok(),
            bio: row.get("bio").ok(),
            affiliation: row.get("affiliation").ok(),
            avatar_hash: row.get("avatar_hash").ok(),
            is_admin,
            is_moderator,
            is_verified: row.get::<_, i64>("is_verified").unwrap_or(0) == 1,
            email_verified: row.get::<_, i64>("email_verified").unwrap_or(0) == 1,
            total_uploads: row.get("total_uploads").unwrap_or(0),
            total_reviews: row.get("total_reviews").unwrap_or(0),
            reputation_score: row.get("reputation_score").unwrap_or(0),
            created_at: row.get("created_at")?,
            last_login: row.get("last_login").ok(),
            role,
        })
    }
    
    /// Get a safe public view of the user (no email)
    pub fn public_view(&self) -> PublicUser {
        PublicUser {
            username: self.username.clone(),
            public_key: self.public_key.clone(),
            display_name: self.display_name.clone(),
            bio: self.bio.clone(),
            affiliation: self.affiliation.clone(),
            avatar_hash: self.avatar_hash.clone(),
            is_verified: self.is_verified,
            total_uploads: self.total_uploads,
            total_reviews: self.total_reviews,
            reputation_score: self.reputation_score,
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub username: String,
    pub public_key: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub affiliation: Option<String>,
    pub avatar_hash: Option<String>,
    pub is_verified: bool,
    pub total_uploads: i64,
    pub total_reviews: i64,
    pub reputation_score: i64,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub public_key: String,
    pub display_name: Option<String>,
}

#[derive(Debug)]
pub struct Session {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

// ============================================================================
// File models
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct File {
    pub id: i64,
    pub uuid: String,
    pub user_id: i64,
    pub username: String,
    pub uploader_name: Option<String>,
    
    pub filename: String,
    pub original_filename: String,
    pub content_type: String,
    pub size: i64,
    pub hash: String,
    
    pub grabnet_cid: Option<String>,
    
    pub title: Option<String>,
    pub description: Option<String>,
    pub is_public: bool,
    
    pub view_count: i64,
    pub download_count: i64,
    
    pub tags: Vec<String>,
    
    pub created_at: String,
    pub updated_at: String,
}

impl File {
    pub fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            uuid: row.get("uuid")?,
            user_id: row.get("user_id")?,
            username: row.get("username").unwrap_or_else(|_| String::new()),
            uploader_name: row.get("uploader_name").ok(),
            
            filename: row.get("filename")?,
            original_filename: row.get("original_filename")?,
            content_type: row.get("content_type")?,
            size: row.get("size")?,
            hash: row.get("hash")?,
            
            grabnet_cid: row.get("grabnet_cid").ok(),
            
            title: row.get("title").ok(),
            description: row.get("description").ok(),
            is_public: row.get::<_, i64>("is_public").unwrap_or(1) == 1,
            
            view_count: row.get("view_count").unwrap_or(0),
            download_count: row.get("download_count").unwrap_or(0),
            
            tags: Vec::new(), // Filled in separately
            
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

#[derive(Debug)]
pub struct NewFile {
    pub uuid: String,
    pub user_id: i64,
    pub filename: String,
    pub original_filename: String,
    pub content_type: String,
    pub size: i64,
    pub hash: String,
    pub grabnet_cid: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub is_public: bool,
}

// ============================================================================
// Review models
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct Review {
    pub id: i64,
    pub file_id: i64,
    pub reviewer_id: i64,
    pub reviewer_username: String,
    pub reviewer_name: Option<String>,
    
    pub rating: i32,
    pub content: Option<String>,
    pub methodology_score: Option<i32>,
    pub clarity_score: Option<i32>,
    pub reproducibility_score: Option<i32>,
    pub significance_score: Option<i32>,
    
    pub helpful_count: i64,
    pub unhelpful_count: i64,
    
    pub created_at: String,
    pub updated_at: String,
}

impl Review {
    pub fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            file_id: row.get("file_id")?,
            reviewer_id: row.get("reviewer_id")?,
            reviewer_username: row.get("reviewer_username").unwrap_or_else(|_| String::new()),
            reviewer_name: row.get("reviewer_name").ok(),
            
            rating: row.get("rating")?,
            content: row.get("content").ok(),
            methodology_score: row.get("methodology_score").ok(),
            clarity_score: row.get("clarity_score").ok(),
            reproducibility_score: row.get("reproducibility_score").ok(),
            significance_score: row.get("significance_score").ok(),
            
            helpful_count: row.get("helpful_count").unwrap_or(0),
            unhelpful_count: row.get("unhelpful_count").unwrap_or(0),
            
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

#[derive(Debug)]
pub struct NewReview {
    pub file_id: i64,
    pub reviewer_id: i64,
    pub rating: i32,
    pub content: Option<String>,
    pub methodology_score: Option<i32>,
    pub clarity_score: Option<i32>,
    pub reproducibility_score: Option<i32>,
    pub significance_score: Option<i32>,
}

// ============================================================================
// API request/response types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub user: Option<PublicUser>,
    pub token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

#[derive(Debug, Default)]
pub struct UploadMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub is_public: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReviewRequest {
    pub rating: i32,
    pub content: Option<String>,
    pub methodology_score: Option<i32>,
    pub clarity_score: Option<i32>,
    pub reproducibility_score: Option<i32>,
    pub significance_score: Option<i32>,
}

/// Review statistics for a file
#[derive(Debug, Serialize)]
pub struct ReviewStats {
    pub count: i64,
    pub avg_rating: f64,
    pub avg_methodology: Option<f64>,
    pub avg_clarity: Option<f64>,
    pub avg_reproducibility: Option<f64>,
    pub avg_significance: Option<f64>,
}
