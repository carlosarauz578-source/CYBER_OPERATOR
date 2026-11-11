"""
Database Module
Manages SQLite database for caching and query history
"""

import sqlite3
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging
import uuid
from functools import wraps
from threading import RLock

logger = logging.getLogger(__name__)


def _synchronized(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class DatabaseManager:
    """Manages SQLite database operations"""
    
    def __init__(self, db_path: str = "cyber_operator.db"):
        self.db_path = Path(db_path)
        self.connection = None
        self._lock = RLock()
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    @_synchronized
    def init_database(self):
        """Initialize database with required tables"""
        self.connect()
        cursor = self.connection.cursor()
        
        # Query history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS query_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_id TEXT UNIQUE,
                target TEXT NOT NULL,
                target_type TEXT,
                selection_mode TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                execution_time REAL,
                success BOOLEAN,
                status TEXT,
                selected_sources TEXT,
                result_count INTEGER,
                result_data TEXT
            )
        """)
        existing_columns = {
            row["name"] for row in cursor.execute("PRAGMA table_info(query_history)")
        }
        for column, definition in (
            ("query_id", "TEXT"),
            ("status", "TEXT"),
            ("selected_sources", "TEXT"),
        ):
            if column not in existing_columns:
                cursor.execute(f"ALTER TABLE query_history ADD COLUMN {column} {definition}")
        
        # Cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_key TEXT UNIQUE NOT NULL,
                source_id TEXT,
                data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                ttl_seconds INTEGER
            )
        """)
        
        # Source status table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS source_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT UNIQUE NOT NULL,
                last_used DATETIME,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                average_response_time REAL,
                last_error TEXT
            )
        """)
        
        # Query results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS query_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_id INTEGER,
                source_id TEXT,
                result_data TEXT,
                execution_time REAL,
                success BOOLEAN,
                error_message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (query_id) REFERENCES query_history(id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_target ON query_history(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON query_history(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_key ON cache(cache_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at)")
        
        self.connection.commit()
        logger.info(f"Database initialized at {self.db_path}")
    
    @_synchronized
    def connect(self):
        """Establish database connection"""
        if self.connection is None:
            self.connection = sqlite3.connect(
                str(self.db_path), check_same_thread=False
            )
            self.connection.row_factory = sqlite3.Row
    
    @_synchronized
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    @_synchronized
    def save_query(self, target: str, target_type: str, selection_mode: str,
                   execution_time: float, success: bool, results: Any,
                   query_id: str = None, selected_sources: List[str] = None,
                   status: str = None) -> int:
        """
        Save query to history.
        
        Args:
            target: Search target
            target_type: Target type (domain, ip, etc.)
            selection_mode: Selection mode used
            execution_time: Query execution time in seconds
            success: Whether query was successful
            results: Query results
            
        Returns:
            Query ID
        """
        cursor = self.connection.cursor()
        result_data = json.dumps(results, default=str)
        query_id = query_id or str(uuid.uuid4())
        selected_sources = selected_sources or []
        
        cursor.execute("""
            INSERT INTO query_history
            (query_id, target, target_type, selection_mode, execution_time,
             success, status, selected_sources, result_count, result_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            query_id, target, target_type, selection_mode, execution_time,
            success, status or ("successful" if success else "failed"),
            json.dumps(selected_sources), self._result_count(results), result_data
        ))
        
        history_id = cursor.lastrowid
        source_results = results.get("findings", {}).get("sources", {}) if isinstance(results, dict) else {}
        for source_id, source_result in source_results.items():
            cursor.execute("""
                INSERT INTO query_results
                (query_id, source_id, result_data, execution_time, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                history_id, source_id, json.dumps(source_result, default=str),
                source_result.get("execution_time", 0), source_result.get("success", False),
                source_result.get("error")
            ))
        self.connection.commit()
        return history_id

    @staticmethod
    def _result_count(results: Any) -> int:
        if isinstance(results, dict):
            return len(results.get("findings", {}).get("sources", {}))
        try:
            return len(results)
        except TypeError:
            return 0
    
    @_synchronized
    def get_query_history(self, limit: int = 100, days: int = 30) -> List[Dict]:
        """
        Get query history.
        
        Args:
            limit: Maximum number of records
            days: Only include queries from last N days
            
        Returns:
            List of query records
        """
        cursor = self.connection.cursor()
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute("""
            SELECT * FROM query_history
            WHERE julianday(timestamp) > julianday(?)
            ORDER BY timestamp DESC
            LIMIT ?
        """, (cutoff_date, limit))
        
        results = []
        for row in cursor.fetchall():
            results.append(dict(row))
        
        return results
    
    @_synchronized
    def get_query_by_target(self, target: str, limit: int = 10) -> List[Dict]:
        """Get query history for a specific target"""
        cursor = self.connection.cursor()
        
        cursor.execute("""
            SELECT * FROM query_history
            WHERE target = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (target, limit))
        
        results = []
        for row in cursor.fetchall():
            results.append(dict(row))
        
        return results

    @_synchronized
    def get_query_by_id(self, query_id: str) -> Optional[Dict]:
        """Return a persisted search by its unique query identifier."""
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT * FROM query_history WHERE query_id = ?",
            (query_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    
    @_synchronized
    def cache_result(self, cache_key: str, data: Dict, source_id: str = None,
                    ttl_seconds: int = 3600) -> None:
        """
        Cache a query result.
        
        Args:
            cache_key: Cache key (e.g., "dns:example.com")
            data: Data to cache
            source_id: Source that provided the data
            ttl_seconds: Time to live in seconds
        """
        cursor = self.connection.cursor()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        data_json = json.dumps(data, default=str)
        
        try:
            cursor.execute("""
                INSERT INTO cache (cache_key, source_id, data, expires_at, ttl_seconds)
                VALUES (?, ?, ?, ?, ?)
            """, (cache_key, source_id, data_json, expires_at, ttl_seconds))
            self.connection.commit()
        except sqlite3.IntegrityError:
            # Update existing cache entry
            cursor.execute("""
                UPDATE cache
                SET data = ?, expires_at = ?, ttl_seconds = ?
                WHERE cache_key = ?
            """, (data_json, expires_at, ttl_seconds, cache_key))
            self.connection.commit()
    
    @_synchronized
    def get_cached_result(self, cache_key: str) -> Optional[Dict]:
        """
        Retrieve cached result if not expired.
        
        Args:
            cache_key: Cache key
            
        Returns:
            Cached data or None if expired/not found
        """
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT data, expires_at FROM cache
            WHERE cache_key = ? AND julianday(expires_at) > julianday('now')
        """, (cache_key,))
        
        row = cursor.fetchone()
        if row:
            return json.loads(row['data'])
        
        return None
    
    @_synchronized
    def clear_expired_cache(self) -> int:
        """Clear expired cache entries"""
        cursor = self.connection.cursor()
        cursor.execute("""
            DELETE FROM cache
            WHERE expires_at < datetime('now')
        """)
        self.connection.commit()
        return cursor.rowcount
    
    @_synchronized
    def update_source_status(self, source_id: str, success: bool,
                            response_time: float, error_message: str = None) -> None:
        """
        Update source status statistics.
        
        Args:
            source_id: Source ID
            success: Whether query was successful
            response_time: Query response time
            error_message: Error message if failed
        """
        cursor = self.connection.cursor()
        
        # Check if exists
        cursor.execute("SELECT id FROM source_status WHERE source_id = ?", (source_id,))
        exists = cursor.fetchone() is not None
        
        if exists:
            if success:
                cursor.execute("""
                    UPDATE source_status
                    SET success_count = success_count + 1,
                        last_used = datetime('now'),
                        last_error = NULL
                    WHERE source_id = ?
                """, (source_id,))
            else:
                cursor.execute("""
                    UPDATE source_status
                    SET failure_count = failure_count + 1,
                        last_error = ?
                    WHERE source_id = ?
                """, (error_message, source_id))
        else:
            cursor.execute("""
                INSERT INTO source_status
                (source_id, last_used, success_count, failure_count, last_error)
                VALUES (?, datetime('now'), ?, ?, ?)
            """, (source_id, 1 if success else 0, 0 if success else 1, error_message))
        
        self.connection.commit()
    
    @_synchronized
    def get_source_stats(self, source_id: str) -> Optional[Dict]:
        """Get statistics for a source"""
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT * FROM source_status WHERE source_id = ?
        """, (source_id,))
        
        row = cursor.fetchone()
        if row:
            return dict(row)
        
        return None
    
    @_synchronized
    def cleanup_old_data(self, days: int = 90) -> int:
        """
        Delete old query history.
        
        Args:
            days: Delete queries older than N days
            
        Returns:
            Number of deleted records
        """
        cursor = self.connection.cursor()
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute("""
            DELETE FROM query_history
            WHERE timestamp < ?
        """, (cutoff_date,))
        
        self.connection.commit()
        return cursor.rowcount
