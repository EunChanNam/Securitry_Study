package study.spring.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;

@Component
public class JwtTokenProvider {

	private static final String AUTHORITIES = "Authorities";

	private final Key key;
	private final long accessTokenValidity;
	private final long refreshTokenValidity;

	public JwtTokenProvider(
		@Value("${jwt.secret-key}") String key,
		@Value("${jwt.access-token-validity}") long accessTokenValidity,
		@Value("${jwt.refresh-token-validity}") long refreshTokenValidity
	) {
		this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(key));
		this.accessTokenValidity = accessTokenValidity;
		this.refreshTokenValidity = refreshTokenValidity;
	}

	public String createAccessToken(Authentication authentication) {
		return createToken(authentication, accessTokenValidity);
	}

	public String createRefreshToken(Authentication authentication) {
		return createToken(authentication, refreshTokenValidity);
	}

	public TokenInfo getPayload(String token) {
		Claims claims = getClaims(token);
		String[] authorities = claims.get(AUTHORITIES).toString().split(",");
		return new TokenInfo(claims.getSubject(), authorities);
	}

	private String createToken(Authentication authentication, long expireTime) {
		Date now = new Date();
		Date expireDate = new Date(now.getTime() + expireTime);

		String authorities = authentication.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.joining(","));

		return Jwts.builder()
			.setSubject(authentication.getName())
			.claim(AUTHORITIES, "ROLE_USER")
			.setIssuedAt(now)
			.setExpiration(expireDate)
			.signWith(key, SignatureAlgorithm.HS256)
			.compact();
	}

	public void validateToken(String token) {
		getClaims(token);
	}

	private Claims getClaims(String token) {
		try {
			return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
		} catch (ExpiredJwtException e) {
			throw new IllegalArgumentException("jwt expire ex");
		} catch (
			SecurityException |
			MalformedJwtException |
			UnsupportedJwtException |
			IllegalArgumentException e
		) {
			throw new IllegalArgumentException("jwt invalid ex");
		}
	}

	record TokenInfo(
		String username,
		String[] authorities
	) {
	}
}
