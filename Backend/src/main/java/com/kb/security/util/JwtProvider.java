package com.kb.security.util;

import com.kb.security.dto.JwtDTO;
import com.kb.security.util.KeyGenerator;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;


@Slf4j
@Component
public class JwtProvider {
    private KeyPair keyPair = KeyGenerator.generateKeyPair();
    private PrivateKey privateKey = keyPair.getPrivate();
    private PublicKey publicKey = keyPair.getPublic();

    static private final long ACCESSTOKEN_VALID_MILISECOND = 1000L * 60 * 60 ; // 1시간
    static private final long REFRESHTOKEN_VALID_MILISECOND = 1000L * 60 * 60 * 24 * 7;

    public JwtDTO generateToken(String subject) {
        try {
            log.debug("Generating access token...");
            String accessToken = Jwts.builder()
                    .setSubject(subject) // subject - 여기서는 Username
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(new Date().getTime() + ACCESSTOKEN_VALID_MILISECOND))
                    .signWith(privateKey, SignatureAlgorithm.ES256)
                    .compact();
            log.debug("Access token generated: {}", accessToken);

            log.debug("Generating refresh token...");
            String refreshToken = Jwts.builder()
                    .setExpiration(new Date(new Date().getTime() + REFRESHTOKEN_VALID_MILISECOND))
                    .signWith(privateKey, SignatureAlgorithm.ES256)
                    .compact();
            log.debug("Refresh token generated: {}", refreshToken);

            return JwtDTO.builder()
                    .grantType("Bearer")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        } catch (Exception e) {
            log.error("Error generating JWT", e);
            throw new RuntimeException("JWT 생성 중 문제가 발생했습니다.", e);
        }
    }

    // JWT Subject(username) 추출 - 해석 불가인 경우 예외 발생

    // 복호화하여 토큰에 있는 username을 꺼내는 메서드
    public String getUsername(String accessToken) {
        Claims claims = parseClaims(accessToken);
        String subject = claims.getSubject();
        return subject;
    }
    // 토큰 검증
    public boolean validateAccessToken(String token){
        try{
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
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
//    // Refresh Token의 유효성 검증
//    public String validateRefreshToken(String token){
//        try {
//            Jws<Claims> claims = Jwts.parserBuilder()
//                    .setSigningKey(publicKey)
//                    .build()
//                    .parseClaimsJws(token);
//            if (!claims.getBody().getExpiration().before(new Date())) {
//                return recreateAccessToken();
//            }
//        }
//    }

    // Claims: 토큰에서 사용할 정보의 조각
    // accessToken을 복호화하고, 만료된 토큰의 경우에도 Claims 반환
    // 만료된 토큰에서 사용자정보를 꺼내어 refreshToken으로 교체할 수 있다
    // 따라서 복호화와 검증을 분류한다
    // parseClaimsJws()메서드가 JWT 토큰의 검증과 파싱 모두 수행
    private Claims parseClaims(String accessToken){
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

}
