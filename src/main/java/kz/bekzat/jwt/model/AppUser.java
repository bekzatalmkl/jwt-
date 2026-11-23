package kz.bekzat.jwt.model;
import java.time.Instant;
public class AppUser extends BaseEntity { private final String username,passwordHash; private final Role role; public AppUser(String u,String p,Role r){super();username=u;passwordHash=p;role=r;} public AppUser(String id,String u,String p,Role r,Instant created){super(id,created);username=u;passwordHash=p;role=r;} public String getUsername(){return username;} public String getPasswordHash(){return passwordHash;} public Role getRole(){return role;} public String getEntityType(){return "USER";} }
