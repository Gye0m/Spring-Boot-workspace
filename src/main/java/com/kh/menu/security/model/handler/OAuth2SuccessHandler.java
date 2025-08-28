package com.kh.menu.security.model.handler;

import java.io.IOException;
import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.kh.menu.security.controller.AuthController;
import com.kh.menu.security.model.dto.CustomOAuth2User;
import com.kh.menu.security.model.provider.JWTProvider;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

	private final JWTProvider jwt;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

		Long id = (Long) oauthUser.getUserId();

		String accessToken = jwt.createAccessToken(id, 30);
		String refreshToken = jwt.createRefreshToken(id, 7);

		ResponseCookie cookie = ResponseCookie
				.from(AuthController.REFRESH_COOKIE, refreshToken)
				.httpOnly(true)
				.secure(false)
				.sameSite("Lax")
				.path("/")
				.maxAge(Duration.ofDays(7))
				.build();
		response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
		
		String redirect = UriComponentsBuilder
				.fromUriString("http://localhost:5173/oauth2/success")
				.queryParam("accessToken", accessToken)
				.build().toUriString();
		
		response.sendRedirect(redirect);
	}
}