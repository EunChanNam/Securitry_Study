package study.spring.security.user;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class UserController {

	@GetMapping("/api/me")
	public String me(@AuthenticationPrincipal UserDetails userDetails) {
		log.info("userInfo : {}, {}", userDetails.getUsername(), userDetails.getAuthorities());
		return userDetails.getUsername();
	}
}
