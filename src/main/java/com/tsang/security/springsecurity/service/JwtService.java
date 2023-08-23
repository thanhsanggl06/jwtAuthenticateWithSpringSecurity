package com.tsang.security.springsecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    public static final String SECRET = "77cf408fc65c6d03ed24e7ffc3e0959bc9925aef2e7ed6c654047e87c2edf411";

    //trich xuat ra username trong payload cua token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //trich xuat thoi gian het han cua token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //phuong thu trich xuat cac claim tu payload cua jwt
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    private Claims extractAllClaims(String token) {
        return Jwts                 // su dung thu vien Jwts de parse token ra
                .parserBuilder()        //su dung parserBuilder de parse voi khoa ky
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token) // Lay noi dung jwt(payload) da dc giai ma
                .getBody();
    }

    //Kiem tra xem token da het han hay chua
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    // kiem tra tinh hop le cua token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    public String generateToken(String username){
        Map<String,Object> claims=new HashMap<>(); //Cac thong tin khac dc them vao payload
        return createToken(claims,username);
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder().setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis())) //Thoi gian tao token
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*2)) //Thoi gian het han token. 30p
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
