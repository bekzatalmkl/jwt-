
package kz.bekzat.jwt.service;

import kz.bekzat.jwt.dao.RefreshTokenDao;
import kz.bekzat.jwt.dao.SecurityEventDao;
import kz.bekzat.jwt.model.SecurityEvent;
import kz.bekzat.jwt.model.TokenStatus;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenDao dao;
    private final SecurityEventDao events;
    private final long days;
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenDao dao,
            SecurityEventDao events,
            @Value("${app.refresh.days}") long days) {

        this.dao = dao;
        this.events = events;
        this.days = days;
    }

    public Issued issue(String userId) {
        String raw = randomToken();
        String family = UUID.randomUUID().toString();

        try (Connection c = dao.connection()) {
            c.setAutoCommit(false);

            dao.insert(
                    c,
                    userId,
                    hash(raw),
                    family,
                    Instant.now().plusSeconds(days * 86400)
            );

            c.commit();
            return new Issued(raw, family);

        } catch (Exception e) {
            throw new IllegalStateException("Issue failed", e);
        }
    }

    public synchronized Result rotate(
            String raw,
            String username,
            String ip) {

        String oldHash = hash(raw);
        String nextToken = randomToken();

        Result result;
        SecurityEvent event = null;

        try (Connection c = dao.connection()) {
            c.setAutoCommit(false);

            var row = dao.find(c, oldHash);

            if (row == null) {
                c.rollback();
                return new Result(
                        false, null, "Unknown refresh token"
                );
            }

            if (row.status() != TokenStatus.ACTIVE
                    || !row.expiresAt().isAfter(Instant.now())) {

                int revoked = dao.revokeFamily(
                        c, row.familyId()
                );

                c.commit();

                event = new SecurityEvent(
                        "TOKEN_REUSE",
                        username,
                        "Replay detected; revoked "
                                + revoked + " active token(s)",
                        ip,
                        Instant.now()
                );

                result = new Result(
                        false,
                        null,
                        "Refresh token reuse detected. Login again."
                );

            } else {

                int changed = dao.markUsed(c, oldHash);

                if (changed != 1) {

                    int revoked = dao.revokeFamily(
                            c, row.familyId()
                    );

                    c.commit();

                    event = new SecurityEvent(
                            "TOKEN_REUSE",
                            username,
                            "Concurrent replay; revoked "
                                    + revoked + " token(s)",
                            ip,
                            Instant.now()
                    );

                    result = new Result(
                            false,
                            null,
                            "Concurrent token reuse detected"
                    );

                } else {

                    dao.insert(
                            c,
                            row.userId(),
                            hash(nextToken),
                            row.familyId(),
                            Instant.now().plusSeconds(days * 86400)
                    );

                    c.commit();

                    result = new Result(
                            true,
                            nextToken,
                            "Refresh token rotated"
                    );
                }
            }

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Refresh transaction failed", e
            );
        }

        // The SQLite connection is closed before logging the event.
        if (event != null) {
            events.save(event);

            System.out.println(
                    "[SECURITY] Refresh token reuse detected"
            );
        }

        return result;
    }

    public static String hash(String value) {
        try {
            byte[] bytes = MessageDigest
                    .getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(bytes);

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String randomToken() {
        byte[] bytes = new byte[48];
        random.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    public record Issued(
            String token,
            String familyId) {}

    public record Result(
            boolean success,
            String refreshToken,
            String message) {}
}
