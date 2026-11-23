package kz.bekzat.jwt.service;

import kz.bekzat.jwt.dao.RefreshTokenDao;
import kz.bekzat.jwt.dao.SecurityEventDao;
import kz.bekzat.jwt.model.TokenStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.Connection;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    RefreshTokenDao dao;

    @Mock
    SecurityEventDao events;

    @Mock
    Connection connection;

    RefreshTokenService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new RefreshTokenService(dao, events, 7);
        when(dao.connection()).thenReturn(connection);
    }

    @Test
    void activeTokenShouldRotateSuccessfully() throws Exception {
        String oldToken = "old-token";
        String hash = RefreshTokenService.hash(oldToken);

        var row = new RefreshTokenDao.TokenRow(
                "user-1",
                "family-1",
                TokenStatus.ACTIVE,
                Instant.now().plusSeconds(3600)
        );

        when(dao.find(connection, hash)).thenReturn(row);
        when(dao.markUsed(connection, hash)).thenReturn(1);

        var result = service.rotate(oldToken, "bekzat", "127.0.0.1");

        assertTrue(result.success());
        assertNotNull(result.refreshToken());
        assertEquals("Refresh token rotated", result.message());

        verify(dao).markUsed(connection, hash);
        verify(dao).insert(
                eq(connection),
                eq("user-1"),
                anyString(),
                eq("family-1"),
                any(Instant.class)
        );
        verify(connection).commit();
    }

    @Test
    void reusedTokenShouldRevokeFamily() throws Exception {
        String oldToken = "used-token";
        String hash = RefreshTokenService.hash(oldToken);

        var row = new RefreshTokenDao.TokenRow(
                "user-1",
                "family-1",
                TokenStatus.USED,
                Instant.now().plusSeconds(3600)
        );

        when(dao.find(connection, hash)).thenReturn(row);
        when(dao.revokeFamily(connection, "family-1")).thenReturn(1);

        var result = service.rotate(oldToken, "bekzat", "127.0.0.1");

        assertFalse(result.success());
        assertNull(result.refreshToken());
        assertTrue(result.message().contains("reuse detected"));

        verify(dao).revokeFamily(connection, "family-1");
        verify(connection).commit();
        verify(events).save(any());
    }

    @Test
    void unknownTokenShouldBeRejected() throws Exception {
        String unknownToken = "unknown-token";
        String hash = RefreshTokenService.hash(unknownToken);

        when(dao.find(connection, hash)).thenReturn(null);

        var result = service.rotate(
                unknownToken,
                "bekzat",
                "127.0.0.1"
        );

        assertFalse(result.success());
        assertNull(result.refreshToken());
        assertEquals("Unknown refresh token", result.message());

        verify(connection).rollback();
        verify(connection, never()).commit();
        verify(dao, never()).insert(
                any(),
                anyString(),
                anyString(),
                anyString(),
                any(Instant.class)
        );
    }
}
