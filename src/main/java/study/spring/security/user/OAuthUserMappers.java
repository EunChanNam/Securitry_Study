package study.spring.security.user;

import java.util.Arrays;
import java.util.function.Function;

import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OAuthUserMappers {

	GOOGLE("google", oAuth2User -> {
		String name = oAuth2User.getAttribute("name");
		return new User("google", oAuth2User.getName(), name);
	})
	;

	private final String provider;
	private final Function<OAuth2User, User> mapper;

	private User map(OAuth2User oAuth2User) {
		return mapper.apply(oAuth2User);
	}

	public static User mapToUser(String provider, OAuth2User oAuth2User) {
		OAuthUserMappers userMapper = Arrays.stream(values())
			.filter(target -> target.getProvider().equalsIgnoreCase(provider))
			.findAny()
			.orElseThrow();

		return userMapper.map(oAuth2User);
	}
}
