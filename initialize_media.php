<?php
/**
 * initialize_media.php
 *
 * Run this script once to set up your SQLite media database.
 * It creates media.db with a "media" table and a simple users table.
 * A default admin user (username “admin”, password “admin123”) is also created.
 * After successful initialization, the script will try to delete itself.
 */

try {
    $db = new PDO('sqlite:../media.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create the media table to store metadata
    $db->exec("
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_type TEXT,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ");

    // Create a users table for media management (for simplicity, only admin users)
    $db->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
    ");

    // Precomputed hash for password "admin123"
    $adminPasswordHash = '$2y$10$S0qz4U5uWpl3nH7x4rMe..ZRoBj2dM4fR3RqN5JebB3jR7Tg7qQ0a';
    $db->exec("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('admin', '$adminPasswordHash');");

    echo "<p>Media database initialized successfully.</p>";

    // Attempt to delete this file for security reasons
    if (unlink(__FILE__)) {
        echo "<p>The initialization script has been deleted.</p>";
    } else {
        echo "<p>Please delete initialize_media.php manually for security reasons.</p>";
    }
} catch (Exception $e) {
    echo "Initialization failed: " . htmlspecialchars($e->getMessage());
}
?>
