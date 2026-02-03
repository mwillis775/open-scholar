//! Database schema and initialization

use rusqlite::Connection;

/// Initialize database schema
pub fn init_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            public_key TEXT UNIQUE NOT NULL,
            display_name TEXT,
            bio TEXT,
            affiliation TEXT,
            avatar_hash TEXT,
            is_admin INTEGER DEFAULT 0,
            is_moderator INTEGER DEFAULT 0,
            is_verified INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            total_uploads INTEGER DEFAULT 0,
            total_reviews INTEGER DEFAULT 0,
            reputation_score INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT
        );

        -- Sessions table
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Files table
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            hash TEXT NOT NULL,
            grabnet_cid TEXT,
            title TEXT,
            description TEXT,
            is_public INTEGER DEFAULT 1,
            view_count INTEGER DEFAULT 0,
            download_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- File tags
        CREATE TABLE IF NOT EXISTS file_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            tag TEXT NOT NULL,
            UNIQUE(file_id, tag),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );

        -- Reviews table
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            reviewer_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
            content TEXT,
            methodology_score INTEGER CHECK(methodology_score IS NULL OR (methodology_score >= 1 AND methodology_score <= 5)),
            clarity_score INTEGER CHECK(clarity_score IS NULL OR (clarity_score >= 1 AND clarity_score <= 5)),
            reproducibility_score INTEGER CHECK(reproducibility_score IS NULL OR (reproducibility_score >= 1 AND reproducibility_score <= 5)),
            significance_score INTEGER CHECK(significance_score IS NULL OR (significance_score >= 1 AND significance_score <= 5)),
            helpful_count INTEGER DEFAULT 0,
            unhelpful_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(file_id, reviewer_id),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Review votes
        CREATE TABLE IF NOT EXISTS review_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            review_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            helpful INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(review_id, user_id),
            FOREIGN KEY (review_id) REFERENCES reviews(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Password reset tokens
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Email verification tokens
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Moderation: Reports
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            reviewed_by INTEGER,
            reviewed_at TEXT,
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        -- Moderation: User bans
        CREATE TABLE IF NOT EXISTS user_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            ban_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            banned_by INTEGER NOT NULL,
            expires_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (banned_by) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Moderation: Content flags
        CREATE TABLE IF NOT EXISTS content_flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_uuid TEXT NOT NULL,
            flag_type TEXT NOT NULL,
            flagged_by INTEGER NOT NULL,
            note TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(file_uuid, flag_type),
            FOREIGN KEY (flagged_by) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Moderation: Action log
        CREATE TABLE IF NOT EXISTS moderation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            moderator_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (moderator_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
        CREATE INDEX IF NOT EXISTS idx_files_content_type ON files(content_type);
        CREATE INDEX IF NOT EXISTS idx_files_public ON files(is_public);
        CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at);
        CREATE INDEX IF NOT EXISTS idx_file_tags_tag ON file_tags(tag);
        CREATE INDEX IF NOT EXISTS idx_reviews_file ON reviews(file_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

        -- Full-text search for files
        CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
            title,
            description,
            filename,
            content='files',
            content_rowid='id'
        );

        -- Triggers to keep FTS in sync
        CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
            INSERT INTO files_fts(rowid, title, description, filename) 
            VALUES (new.id, new.title, new.description, new.filename);
        END;

        CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
            INSERT INTO files_fts(files_fts, rowid, title, description, filename) 
            VALUES ('delete', old.id, old.title, old.description, old.filename);
        END;

        CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
            INSERT INTO files_fts(files_fts, rowid, title, description, filename) 
            VALUES ('delete', old.id, old.title, old.description, old.filename);
            INSERT INTO files_fts(rowid, title, description, filename) 
            VALUES (new.id, new.title, new.description, new.filename);
        END;
        "#,
    )?;

    Ok(())
}
