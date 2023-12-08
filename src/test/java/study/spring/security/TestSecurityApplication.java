package study.spring.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration(proxyBeanMethods = false)
public class TestSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.from(SecurityApplication::main).with(TestSecurityApplication.class).run(args);
	}

}
