package study.spring.security.jwt;

import static study.spring.security.jwt.JwtTokenProvider.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final String AUTHORIZATION = "AUTHORIZATION";

	private final JwtTokenProvider provider;
	private final UserDetailsService userDetailsService;

	private Authentication getAuthentication(HttpServletRequest request) {
		//헤더 검증 필요
		String token = request.getHeader(AUTHORIZATION);
		if (StringUtils.hasText(token)) {
			TokenInfo tokenInfo = provider.getPayload(token);

			List<SimpleGrantedAuthority> authorities = Arrays.stream(tokenInfo.authorities())
				.map(SimpleGrantedAuthority::new)
				.toList();

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
				userDetailsService.loadUserByUsername(tokenInfo.username()),
				null,
				authorities
			);
			authentication.setDetails(new WebAuthenticationDetails(request));
			return authentication;
		}
		return null;
	}

	@Override
	protected void doFilterInternal(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain filterChain
	) throws ServletException, IOException {
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			Authentication authentication = getAuthentication(request);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		filterChain.doFilter(request, response);
	}
}
