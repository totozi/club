package org.zerock.club.security.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJws;
import lombok.extern.log4j.Log4j2;

import java.time.ZonedDateTime;
import java.util.Date;

@Log4j2
public class JWTUtil {

    private String secretKey = "zerock12345678";

    // 1month
    private long expire = 60; // minute

    // JWT 토큰 생성
    public String generateToken(String content) throws Exception {

        return Jwts.builder()
                .setIssuedAt(new Date())
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(expire).toInstant())) // 만료기간
                //.setExpiration(Date.from(ZonedDateTime.now().plusSeconds(1).toInstant()))
                .claim("sub", content) // sub라는 이름의 Claim에는 사용자의 이메일 주소를 넣어서 나중에 사용할 수 있도록 구성
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes("UTF-8")) // 시그니처를 위한 암호화
                .compact();

    }

    // 인코딩된 문자열에서 원하는 값을 추출하는 역할
    // 검증 : 만료기간
    public String validateAndExtract(String tokenStr) throws Exception {

        String contentValue = null;

        try {

            DefaultJws defaultJws = (DefaultJws) Jwts.parser()
                    .setSigningKey(secretKey.getBytes("UTF-8"))
                    .parseClaimsJws(tokenStr);

            log.info(defaultJws);
            log.info(defaultJws.getBody().getClass());

            DefaultClaims claims = (DefaultClaims) defaultJws.getBody();

            log.info("--------------------------");

            contentValue = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            log.error(e.getMessage());
            contentValue = null;
        }

        return contentValue;

    }

}
