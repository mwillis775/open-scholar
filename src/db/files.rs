//! File management

use rusqlite::params;

use crate::db::Database;
use crate::models::{File, NewFile};

impl Database {
    /// Create a new file record
    pub fn create_file(&self, new_file: NewFile, tags: Option<Vec<String>>) -> anyhow::Result<File> {
        let conn = self.conn();
        
        conn.execute(
            r#"
            INSERT INTO files (
                uuid, user_id, filename, original_filename, content_type,
                size, hash, grabnet_cid, title, description, is_public
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                new_file.uuid,
                new_file.user_id,
                new_file.filename,
                new_file.original_filename,
                new_file.content_type,
                new_file.size,
                new_file.hash,
                new_file.grabnet_cid,
                new_file.title,
                new_file.description,
                new_file.is_public as i64,
            ],
        )?;
        
        let file_id = conn.last_insert_rowid();
        
        // Add tags
        if let Some(tags) = tags {
            for tag in tags {
                conn.execute(
                    "INSERT OR IGNORE INTO file_tags (file_id, tag) VALUES (?1, ?2)",
                    params![file_id, tag.to_lowercase().trim()],
                )?;
            }
        }
        
        // Update user stats
        conn.execute(
            "UPDATE users SET total_uploads = total_uploads + 1 WHERE id = ?1",
            params![new_file.user_id],
        )?;
        
        drop(conn);
        self.get_file_by_id(file_id)
    }
    
    /// Get file by ID
    pub fn get_file_by_id(&self, id: i64) -> anyhow::Result<File> {
        let conn = self.conn();
        
        let file = conn.query_row(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.id = ?1
            "#,
            params![id],
            |row| File::from_row(row),
        )?;
        
        let tags: Vec<String> = conn
            .prepare("SELECT tag FROM file_tags WHERE file_id = ?1")?
            .query_map(params![id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(File { tags, ..file })
    }
    
    /// Get file by UUID
    pub fn get_file_by_uuid(&self, uuid: &str) -> anyhow::Result<Option<File>> {
        let conn = self.conn();
        
        let result = conn.query_row(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.uuid = ?1
            "#,
            params![uuid],
            |row| File::from_row(row),
        );
        
        match result {
            Ok(file) => {
                let tags: Vec<String> = conn
                    .prepare("SELECT tag FROM file_tags WHERE file_id = ?1")?
                    .query_map(params![file.id], |row| row.get(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                
                Ok(Some(File { tags, ..file }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    
    /// Get files by user
    pub fn get_files_by_user(&self, user_id: i64, limit: u32, offset: u32) -> anyhow::Result<Vec<File>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.user_id = ?1
            ORDER BY f.created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )?;
        
        let files: Vec<File> = stmt
            .query_map(params![user_id, limit, offset], |row| File::from_row(row))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(files)
    }
    
    /// Get recent public files
    pub fn get_recent_files(&self, limit: u32, offset: u32) -> anyhow::Result<Vec<File>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.is_public = 1
            ORDER BY f.created_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )?;
        
        let files: Vec<File> = stmt
            .query_map(params![limit, offset], |row| File::from_row(row))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(files)
    }
    
    /// Get files by content type
    pub fn get_files_by_type(&self, content_type: &str, limit: u32, offset: u32) -> anyhow::Result<Vec<File>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.is_public = 1 AND f.content_type LIKE ?1
            ORDER BY f.created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )?;
        
        let files: Vec<File> = stmt
            .query_map(params![content_type, limit, offset], |row| File::from_row(row))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(files)
    }
    
    /// Get files by tag
    pub fn get_files_by_tag(&self, tag: &str, limit: u32, offset: u32) -> anyhow::Result<Vec<File>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            JOIN file_tags ft ON f.id = ft.file_id
            WHERE f.is_public = 1 AND ft.tag = ?1
            ORDER BY f.created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )?;
        
        let files: Vec<File> = stmt
            .query_map(params![tag.to_lowercase(), limit, offset], |row| File::from_row(row))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(files)
    }
    
    /// Search files using FTS
    pub fn search_files(&self, query: &str, limit: u32) -> anyhow::Result<Vec<File>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name
            FROM files f
            JOIN users u ON f.user_id = u.id
            JOIN files_fts fts ON f.id = fts.rowid
            WHERE f.is_public = 1 AND files_fts MATCH ?1
            ORDER BY rank
            LIMIT ?2
            "#,
        )?;
        
        let files: Vec<File> = stmt
            .query_map(params![query, limit], |row| File::from_row(row))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(files)
    }
    
    /// Get files awaiting peer review (few or no reviews)
    pub fn get_files_needing_review(&self, limit: u32, offset: u32) -> anyhow::Result<Vec<File>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT f.*, u.username, u.display_name as uploader_name,
                   (SELECT COUNT(*) FROM reviews r WHERE r.file_id = f.id) as review_count
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.is_public = 1
            GROUP BY f.id
            HAVING review_count < 3
            ORDER BY review_count ASC, f.created_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )?;
        
        let files: Vec<File> = stmt
            .query_map(params![limit, offset], |row| File::from_row(row))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(files)
    }
    
    /// Get popular tags
    pub fn get_popular_tags(&self, limit: u32) -> anyhow::Result<Vec<(String, i64)>> {
        let conn = self.conn();
        
        let mut stmt = conn.prepare(
            r#"
            SELECT tag, COUNT(*) as count
            FROM file_tags
            GROUP BY tag
            ORDER BY count DESC
            LIMIT ?1
            "#,
        )?;
        
        let tags: Vec<(String, i64)> = stmt
            .query_map(params![limit], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        
        Ok(tags)
    }
    
    /// Update file metadata
    pub fn update_file(&self, uuid: &str, title: Option<&str>, description: Option<&str>, is_public: Option<bool>) -> anyhow::Result<()> {
        let conn = self.conn();
        
        if let Some(t) = title {
            conn.execute(
                "UPDATE files SET title = ?1, updated_at = datetime('now') WHERE uuid = ?2",
                params![t, uuid],
            )?;
        }
        
        if let Some(d) = description {
            conn.execute(
                "UPDATE files SET description = ?1, updated_at = datetime('now') WHERE uuid = ?2",
                params![d, uuid],
            )?;
        }
        
        if let Some(p) = is_public {
            conn.execute(
                "UPDATE files SET is_public = ?1, updated_at = datetime('now') WHERE uuid = ?2",
                params![p as i64, uuid],
            )?;
        }
        
        Ok(())
    }
    
    /// Delete a file
    pub fn delete_file(&self, uuid: &str) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM files WHERE uuid = ?1", params![uuid])?;
        Ok(())
    }
    
    /// Increment view count
    pub fn increment_view_count(&self, uuid: &str) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE files SET view_count = view_count + 1 WHERE uuid = ?1",
            params![uuid],
        )?;
        Ok(())
    }
    
    /// Increment download count
    pub fn increment_download_count(&self, uuid: &str) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE files SET download_count = download_count + 1 WHERE uuid = ?1",
            params![uuid],
        )?;
        Ok(())
    }
    
    // =========================================================================
    // Admin Methods
    // =========================================================================
    
    /// List all files for admin (with pagination)
    pub fn list_files_admin(&self, offset: i64, limit: i64, search: Option<&str>) -> anyhow::Result<(Vec<serde_json::Value>, i64)> {
        let conn = self.conn();
        
        // Build query based on search
        let (query, count_query) = if search.is_some() {
            (
                r#"
                SELECT f.uuid, f.filename, f.original_filename, f.title, f.content_type, 
                       f.size, f.is_public, f.view_count, f.download_count, f.created_at,
                       u.username, u.id as user_id
                FROM files f
                JOIN users u ON f.user_id = u.id
                WHERE f.filename LIKE ?1 OR f.title LIKE ?1 OR u.username LIKE ?1
                ORDER BY f.created_at DESC
                LIMIT ?2 OFFSET ?3
                "#,
                "SELECT COUNT(*) FROM files f JOIN users u ON f.user_id = u.id WHERE f.filename LIKE ?1 OR f.title LIKE ?1 OR u.username LIKE ?1"
            )
        } else {
            (
                r#"
                SELECT f.uuid, f.filename, f.original_filename, f.title, f.content_type, 
                       f.size, f.is_public, f.view_count, f.download_count, f.created_at,
                       u.username, u.id as user_id
                FROM files f
                JOIN users u ON f.user_id = u.id
                ORDER BY f.created_at DESC
                LIMIT ?1 OFFSET ?2
                "#,
                "SELECT COUNT(*) FROM files"
            )
        };
        
        let search_pattern = search.map(|s| format!("%{}%", s));
        
        let total: i64 = if let Some(ref pattern) = search_pattern {
            conn.query_row(count_query, [pattern], |row| row.get(0))?
        } else {
            conn.query_row(count_query, [], |row| row.get(0))?
        };
        
        let mut stmt = conn.prepare(query)?;
        let mut files = Vec::new();
        
        let rows = if let Some(ref pattern) = search_pattern {
            stmt.query(rusqlite::params![pattern, limit, offset])?
        } else {
            stmt.query(rusqlite::params![limit, offset])?
        };
        
        let mut rows = rows;
        while let Some(row) = rows.next()? {
            files.push(serde_json::json!({
                "uuid": row.get::<_, String>(0)?,
                "filename": row.get::<_, String>(1)?,
                "original_filename": row.get::<_, String>(2)?,
                "title": row.get::<_, Option<String>>(3)?,
                "content_type": row.get::<_, String>(4)?,
                "size": row.get::<_, i64>(5)?,
                "is_public": row.get::<_, i32>(6)? != 0,
                "view_count": row.get::<_, i64>(7)?,
                "download_count": row.get::<_, i64>(8)?,
                "created_at": row.get::<_, String>(9)?,
                "username": row.get::<_, String>(10)?,
                "user_id": row.get::<_, i64>(11)?,
            }));
        }
        
        Ok((files, total))
    }
    
    /// Delete file by UUID (for admin use)
    pub fn delete_file_by_uuid(&self, uuid: &str) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM files WHERE uuid = ?1", params![uuid])?;
        Ok(())
    }
}
