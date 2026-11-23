package kz.bekzat.jwt.model;
import java.time.Instant; import java.util.UUID;
public abstract class BaseEntity implements Auditable { private final String id; private final Instant createdAt; protected BaseEntity(){this(UUID.randomUUID().toString(),Instant.now());} protected BaseEntity(String id,Instant createdAt){this.id=id;this.createdAt=createdAt;} public String getId(){return id;} public Instant getCreatedAt(){return createdAt;} public abstract String getEntityType(); }
