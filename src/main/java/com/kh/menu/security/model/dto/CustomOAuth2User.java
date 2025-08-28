package com.kh.menu.security.model.dto;

import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

public class CustomOAuth2User extends DefaultOAuth2User {

	private final Long userId; // Users테이블의 pk값

	public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes,
			String nameAttributeKey, Long userId) {
		super(authorities, attributes, nameAttributeKey);
		this.userId = userId;
	}

	public Long getUserId() {
		return userId;
	}
}