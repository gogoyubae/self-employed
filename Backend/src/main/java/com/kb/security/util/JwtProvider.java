package com.kb.security.util;

import com.kb.security.dto.JwtDTO;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtProvider {
    private String secretKey = "9b42d3e2a206b52a7e9bede291602e0272d30e1821ff1ae1d786d08d2b650242";
    private Key key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    static private final long ACCESSTOKEN_VALID_MILISECOND = 1000L * 60 * 60 ; // 1시간
    static private final long REFRESHTOKEN_VALID_MILISECOND = 1000L * 60 * 60 * 24 * 7;

    public JwtDTO generateToken(String subject) {
        String accessToken = Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + ACCESSTOKEN_VALID_MILISECOND))
                .signWith(key, SignatureAlgorithm.ES256)
                .compact();
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(new Date().getTime() + REFRESHTOKEN_VALID_MILISECOND))
                .signWith(key, SignatureAlgorithm.ES256).
                compact();
        return JwtDTO.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // JWT Subject(username) 추출 - 해석 불가인 경우 예외 발생

    // 복호화하여 토큰에 있는 username을 꺼내는 메서드
    public String getUsername(String accessToken) {
        Claims claims = parseClaims(accessToken);
        String subject = claims.getSubject();
        return subject;
    }
    // 토큰 검증
    public boolean validateToken(String token){
        try{
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e){
            log.info("invalid JWT", e);
        } catch (ExpiredJwtException e){
            log.info("Expired JWT", e);
        } catch (UnsupportedJwtException e){
            log.info("Unsupported JWT", e);
        } catch (IllegalArgumentException e){
            log.info("JWT Claims string is empty", e);
        } catch (SignatureException e){
            log.info("Invalid JWT signature", e);
        }
        return false;
    }

    // Claims: 토큰에서 사용할 정보의 조각
    // accessToken을 복호화하고, 만료된 토큰의 경우에도 Claims 반환
    // 만료된 토큰에서 사용자정보를 꺼내어 refreshToken으로 교체할 수 있다
    // 따라서 복호화와 검증을 분류한다
    // parseClaimsJws()메서드가 JWT 토큰의 검증과 파싱 모두 수행
    private Claims parseClaims(String accessToken){
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

}
