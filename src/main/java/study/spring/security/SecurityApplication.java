package study.spring.security;

import java.util.List;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import study.spring.security.user.User;
import study.spring.security.user.UserRepository;

@SpringBootApplication
@RequiredArgsConstructor
public class SecurityApplication {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	// @PostConstruct
	public void setUp() {
		User user = new User(
			"user",
			passwordEncoder.encode("user123"),
			"userA",
			"ROLE_USER"
		);

		User admin = new User(
			"admin",
			passwordEncoder.encode("admin123"),
			"admin",
			"ROLE_ADMIN"
		);

		userRepository.saveAll(List.of(user, admin));
	}
}
