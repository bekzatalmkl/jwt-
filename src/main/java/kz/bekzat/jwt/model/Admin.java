package kz.bekzat.jwt.model;
public class Admin extends AppUser { public Admin(String u,String p){super(u,p,Role.ADMIN);} @Override public String getEntityType(){return "ADMIN";} }
