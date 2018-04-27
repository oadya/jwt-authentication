package com.sc.jwt.security.token;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.sc.jwt.security.util.SecurityConstants;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;

@Component
public class JwtTokenGenrator implements Serializable {
    
	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());
	
	private static final long serialVersionUID = -66119377682535579L;

	private Clock clock = DefaultClock.INSTANCE;
    
    private transient byte[] keyHMAC = SecurityConstants.SECRET.getBytes();
    
    
    
    public String getUsernameFromToken(String token) {
    	return getClaimFromToken(token, Claims::getSubject);
    }


    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
            .setSigningKey(this.keyHMAC)
            .parseClaimsJws(token)
            .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(clock.now());
    }


    public String generateToken(JwtAuthUser jwtAuthUser) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", jwtAuthUser.getId());
        claims.put("login", jwtAuthUser.getLogin());
        claims.put("email", jwtAuthUser.getEmail());
        claims.put("name", jwtAuthUser.getName());
        claims.put("firstName", jwtAuthUser.getFirstName());
        claims.put("permissions", jwtAuthUser.getPermissions());
        return doGenerateToken(claims, jwtAuthUser.getName());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        final Date createdDate = clock.now();
        final Date expirationDate = calculateExpirationDate(createdDate);

        return Jwts.builder()
            .setClaims(claims)
            .setId(UUID.randomUUID().toString())
            .setSubject(subject)
            .setIssuedAt(createdDate)
            .setExpiration(expirationDate)
            .signWith(SignatureAlgorithm.HS512, this.keyHMAC)
            .compact();
    }
    
    
    public Boolean validateToken(String token) {
        return (!isTokenExpired(token));
    }

    private Date calculateExpirationDate(Date createdDate) {
      return new Date(createdDate.getTime() + SecurityConstants.EXPIRATION_TIME); 
    }
}