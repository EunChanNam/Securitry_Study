package study.spring.security.config;

import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class CustomAuthenticationHandler {

	@Async("hello")
	@EventListener
	public void logAuthenticationSuccess(AuthenticationSuccessEvent event) {
		log.info("success result : {}", event.getAuthentication().getPrincipal());
	}

	@Async
	@EventListener
	public void logAuthenticationFail(AuthenticationFailureBadCredentialsEvent event) {
		log.info("fail result : {}", event.getAuthentication().getPrincipal());
	}
}
