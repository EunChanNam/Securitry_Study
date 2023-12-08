package study.spring.security.oauth;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import study.spring.security.jwt.JwtTokenProvider;
import study.spring.security.user.UserService;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

	private final JwtTokenProvider tokenProvider;
	private final UserService userService;

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication
	) throws IOException {
		log.info("OAuth Login Success!!");
		if (authentication instanceof OAuth2AuthenticationToken authenticationToken) {
			String provider = authenticationToken.getAuthorizedClientRegistrationId();
			OAuth2User oAuth2User = authenticationToken.getPrincipal();
			userService.join(oAuth2User, provider);

			log.info("oAuthUser's role : {}", authenticationToken.getAuthorities());
			String accessToken = tokenProvider.createAccessToken(authenticationToken);
			String refreshToken = tokenProvider.createRefreshToken(authenticationToken);

			String url = UriComponentsBuilder.fromUriString("https://mydomain" + "/welcome")
				.queryParam("access-token", accessToken)
				.queryParam("refresh-token", refreshToken)
				.queryParam("provider", provider)
				.build()
				.toUri()
				.toString();

			response.sendRedirect(url);
		}
	}
}
