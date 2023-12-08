package study.spring.security.config;

import java.util.Collections;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import study.spring.security.jwt.JwtAuthenticationFilter;
import study.spring.security.jwt.JwtTokenProvider;

@Configuration
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig {

	private static final String ADMIN = "ADMIN";
	private static final String USER = "USER";

	private final ApplicationContext applicationContext;
	private final JwtTokenProvider jwtTokenProvider;
	private final UserDetailsService userDetailsService;
	private final AuthenticationSuccessHandler authenticationSuccessHandler;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JdbcOAuth2AuthorizedClientService jdbcOAuth2AuthorizedClientService(
		JdbcOperations jdbcOperations,
		ClientRegistrationRepository clientRegistrationRepository
	) {
		return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
	}

	@Bean
	public OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(
		OAuth2AuthorizedClientService oAuth2AuthorizedClientService
	) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(oAuth2AuthorizedClientService);
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
			.csrf(AbstractHttpConfigurer::disable)
			.headers(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.logout(AbstractHttpConfigurer::disable)
			.httpBasic(AbstractHttpConfigurer::disable)
			.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.anonymous(AbstractHttpConfigurer::disable)
			.cors(configurer -> configurer.configurationSource(request -> {
					CorsConfiguration cors = new CorsConfiguration();
					cors.setAllowedOrigins(List.of("http://localhost:8080"));
					cors.setAllowedMethods(Collections.singletonList("*"));
					cors.setAllowedHeaders(Collections.singletonList("*"));
					cors.setAllowCredentials(true);
					return cors;
				}
			))
			.authorizeHttpRequests(registry -> registry
				.requestMatchers("/api/me").hasRole(ADMIN)
				.anyRequest().permitAll()
			)
			.exceptionHandling(configurer -> configurer
				.accessDeniedHandler(accessDeniedHandler())
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
			.addFilterBefore(
				new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService),
				UsernamePasswordAuthenticationFilter.class)
			.oauth2Login(customizer -> customizer.successHandler(authenticationSuccessHandler))
			.oauth2Client(customizer -> customizer.authorizedClientRepository(
				applicationContext.getBean(OAuth2AuthorizedClientRepository.class)
			))
			.build();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return ((request, response, e) -> {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			Object principal = authentication != null ? authentication.getPrincipal() : null;
			log.warn("{} is denied", principal, e);
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType(MediaType.TEXT_PLAIN_VALUE);
			response.getWriter().write("## ACCESS DENIED ##");
			response.getWriter().flush();
			response.getWriter().close();
		});
	}
}
