package kz.bekzat.jwt.service;
public interface TokenOperations { String createAccessToken(String username,String role); boolean isAccessTokenValid(String token); }
