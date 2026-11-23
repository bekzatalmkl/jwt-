
package kz.bekzat.jwt.db;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.sqlite.SQLiteConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

@Component
public class DatabaseConnection {

    @Value("${app.database.url}")
    private String url;

    public Connection open() throws SQLException {
        SQLiteConfig config = new SQLiteConfig();

        config.setBusyTimeout(5000);
        config.enforceForeignKeys(true);
        config.setTransactionMode(
                SQLiteConfig.TransactionMode.IMMEDIATE
        );

        return DriverManager.getConnection(
                url,
                config.toProperties()
        );
    }

    @PostConstruct
    public void init() {
        try {
            Path databasePath = Path.of(
                    url.substring("jdbc:sqlite:".length())
            );

            if (databasePath.getParent() != null) {
                Files.createDirectories(databasePath.getParent());
            }

            try (
                    Connection connection = open();
                    Statement statement = connection.createStatement()
            ) {
                statement.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """);

                statement.execute("""
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        token_hash TEXT UNIQUE NOT NULL,
                        family_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                    """);

                statement.execute("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        username TEXT NOT NULL,
                        description TEXT NOT NULL,
                        ip_address TEXT,
                        timestamp TEXT NOT NULL
                    )
                    """);

            }
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "SQLite init failed",
                    exception
            );
        }
    }
}
