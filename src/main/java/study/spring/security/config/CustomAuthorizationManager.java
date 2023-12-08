package study.spring.security.config;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

	@Override
	public AuthorizationDecision check(
		Supplier<Authentication> authentication,
		RequestAuthorizationContext context
	) {
		/**
		 * 커스텀 인가 처리
		 */
		return new AuthorizationDecision(true);
	}
}
