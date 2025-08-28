package com.kh.menu.security.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.kh.menu.security.model.provider.JWTProvider;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

	private final JWTProvider jwt;

	// accessToken인증 확인용 필터
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// 1) 요청 header에서 Authorization 추출
		String header = request.getHeader("Authorization");

		if (header != null && header.startsWith("Bearer ")) {

			try {
				// 2) 토큰에서 userId 추출
				String token = header.substring(7).trim();
				Long userId = jwt.getUserId(token);

				log.debug("userId : {}", userId);
				UsernamePasswordAuthenticationToken authToken = 
						new UsernamePasswordAuthenticationToken(userId, null,
						List.of(new SimpleGrantedAuthority("ROLE_USER")));
				// 인증 처리 끝
				SecurityContextHolder.getContext().setAuthentication(authToken);
			} catch (ExpiredJwtException e) {
				// 만료된 토큰인 경우
				SecurityContextHolder.clearContext();
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED); // 401상태
				return;
			}
		}
		filterChain.doFilter(request, response);
	}
}