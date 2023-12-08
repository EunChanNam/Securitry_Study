package study.spring.security.user;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
@Table(name = "users")
public class User implements UserDetails {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	private String username;

	private String password;

	private String provider;

	private String providerId;

	private String name;

	private String role;

	public User(String username, String password, String name, String role) {
		this.username = username;
		this.password = password;
		this.name = name;
		this.role = role;
	}

	public User(String provider, String providerId, String name) {
		this.provider = provider;
		this.username = providerId;
		this.name = name;
		this.role = "USER";
	}

	public void updateByOAuth(String name) {
		this.name = name;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singletonList(() -> role);
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
