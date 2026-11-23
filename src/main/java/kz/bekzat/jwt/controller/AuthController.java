
package kz.bekzat.jwt.controller;

import kz.bekzat.jwt.analytics.SecurityAnalyticsService;
import kz.bekzat.jwt.export.CsvExportService;
import kz.bekzat.jwt.service.*;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Path;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthService auth;
    private final RefreshTokenService refresh;
    private final JwtService jwt;
    private final SecurityAnalyticsService analytics;
    private final CsvExportService csv;

    public AuthController(
            AuthService auth,
            RefreshTokenService refresh,
            JwtService jwt,
            SecurityAnalyticsService analytics,
            CsvExportService csv) {

        this.auth = auth;
        this.refresh = refresh;
        this.jwt = jwt;
        this.analytics = analytics;
        this.csv = csv;
    }

    @PostMapping("/auth/register")
    public Map<String, Object> register(
            @RequestBody Credentials credentials) {

        return auth.register(
                credentials.username(),
                credentials.password()
        );
    }

    @PostMapping("/auth/login")
    public Map<String, Object> login(
            @RequestBody Credentials credentials) {

        return auth.login(
                credentials.username(),
                credentials.password()
        );
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refresh(
            @RequestBody RefreshRequest request) {

        var result = refresh.rotate(
                request.refreshToken(),
                "api-user",
                "127.0.0.1"
        );

        if (!result.success()) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", result.message()));
        }

        return ResponseEntity.ok(Map.of(
                "refreshToken", result.refreshToken(),
                "message", result.message()
        ));
    }

    @GetMapping("/user/profile")
    public ResponseEntity<?> profile(
            @RequestHeader(
                    value = "Authorization",
                    required = false) String header) {

        if (!validBearer(header)) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid or missing token"));
        }

        var claims = jwt.parse(header.substring(7));

        return ResponseEntity.ok(Map.of(
                "username", claims.getSubject(),
                "role", claims.get("role")
        ));
    }

    @GetMapping("/admin/analytics")
    public ResponseEntity<?> analytics(
            @RequestHeader(
                    value = "Authorization",
                    required = false) String header) {

        ResponseEntity<?> denied = checkAdmin(header);

        if (denied != null) {
            return denied;
        }

        return ResponseEntity.ok(analytics.countByType());
    }

    @GetMapping("/admin/export")
    public ResponseEntity<?> export(
            @RequestHeader(
                    value = "Authorization",
                    required = false) String header) throws Exception {

        ResponseEntity<?> denied = checkAdmin(header);

        if (denied != null) {
            return denied;
        }

        Path path = csv.export(
                Path.of("exports/security-report.csv")
        );

        return ResponseEntity.ok(
                Map.of("file", path.toString())
        );
    }

    private boolean validBearer(String header) {

        return header != null
                && header.startsWith("Bearer ")
                && jwt.isAccessTokenValid(header.substring(7));
    }

    private ResponseEntity<?> checkAdmin(String header) {

        if (!validBearer(header)) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Authentication required"));
        }

        var claims = jwt.parse(header.substring(7));

        if (!"ADMIN".equals(claims.get("role", String.class))) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Admin access required"));
        }

        return null;
    }

    public record Credentials(
            String username,
            String password) {}

    public record RefreshRequest(
            String refreshToken) {}
}
