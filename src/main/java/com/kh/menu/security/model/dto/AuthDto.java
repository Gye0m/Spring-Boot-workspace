package com.kh.menu.security.model.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

public class AuthDto {
	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	public static class LoginRequest {
		private String email;
		private String password;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	public static class AuthResult {
		private String accessToken;
		private String refreshToken;
		private User user;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	public static class User {
		private Long id;
		private String email;
		private String password;
		private String name;
		private String profile;
		private List<String> roles;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	public static class UserCredential {
		private Long userId;
		private String password;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	public static class UserAuthority {
		private Long userId;
		private List<String> roles;
	}

	@Data
	@NoArgsConstructor
	@AllArgsConstructor
	@Builder
	public static class UserIdentities {
		private Long id;
		private Long userId;
		private String accessToken;
		private String provider;
		private String providerUserId;
	}
}