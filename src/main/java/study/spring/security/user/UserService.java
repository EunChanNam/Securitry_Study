package study.spring.security.user;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;

	public User join(OAuth2User oAuth2User, String provider) {
		User user = OAuthUserMappers.mapToUser(provider, oAuth2User);

		userRepository.findByProviderAndProviderId(provider, oAuth2User.getName())
			.ifPresentOrElse(
				findUser -> findUser.updateByOAuth(user.getName()),
				() -> userRepository.save(user)
			);

		return user;
	}
}
