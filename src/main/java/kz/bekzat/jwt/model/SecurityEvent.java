package kz.bekzat.jwt.model;
import java.time.Instant;
public record SecurityEvent(String eventType,String username,String description,String ipAddress,Instant timestamp) {}
