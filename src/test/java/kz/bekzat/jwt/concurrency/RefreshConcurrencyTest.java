package kz.bekzat.jwt.concurrency;

import kz.bekzat.jwt.dao.*;
import kz.bekzat.jwt.db.DatabaseConnection;
import kz.bekzat.jwt.service.RefreshTokenService;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.sql.*;
import java.time.Instant;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

class RefreshConcurrencyTest {

    @TempDir
    Path tempDir;

    @Test
    void concurrentRefreshMustNotSucceedTwice() throws Exception {

        DatabaseConnection db = new DatabaseConnection();

        Field field = DatabaseConnection.class.getDeclaredField("url");
        field.setAccessible(true);
        field.set(db, "jdbc:sqlite:" +
                tempDir.resolve("race.db").toAbsolutePath());

        db.init();

        try (Connection c = db.open();
             PreparedStatement p = c.prepareStatement(
                 "INSERT INTO users VALUES(?,?,?,?,?)")) {

            p.setString(1, "test-user-id");
            p.setString(2, "race-user");
            p.setString(3, "hash");
            p.setString(4, "USER");
            p.setString(5, Instant.now().toString());
            p.executeUpdate();
        }

        RefreshTokenService service = new RefreshTokenService(
                new RefreshTokenDao(db),
                new SecurityEventDao(db),
                7
        );

        String token = service.issue("test-user-id").token();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch gate = new CountDownLatch(1);

        try {
            Callable<Boolean> request = () -> {
                gate.await();
                return service.rotate(
                        token, "race-user", "127.0.0.1"
                ).success();
            };

            Future<Boolean> first = pool.submit(request);
            Future<Boolean> second = pool.submit(request);

            gate.countDown();

            boolean result1 = first.get(15, TimeUnit.SECONDS);
            boolean result2 = second.get(15, TimeUnit.SECONDS);

            long successes = (result1 ? 1 : 0)
                    + (result2 ? 1 : 0);

            assertEquals(1, successes,
                    "Exactly one rotation must succeed");

            try (Connection c = db.open();
                 Statement s = c.createStatement();
                 ResultSet r = s.executeQuery(
                     "SELECT COUNT(*) FROM refresh_tokens " +
                     "WHERE status='ACTIVE'")) {

                assertTrue(r.next());
                assertEquals(0, r.getInt(1),
                        "Replay must revoke the active family token");
            }
        } finally {
            pool.shutdownNow();
        }
    }
}