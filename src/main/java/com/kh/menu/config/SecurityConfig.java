package com.kh.menu.config;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.kh.menu.security.filter.JWTAuthenticationFilter;
import com.kh.menu.security.model.handler.OAuth2SuccessHandler;
import com.kh.menu.security.model.service.OAuth2Service;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http,
			JWTAuthenticationFilter jwtFilter,
			OAuth2Service oauth2Service,
			OAuth2SuccessHandler oauth2SuccessHandler
			) throws Exception{
		
		http
			//Cors관련 빈객체 등록
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			// CSRF는 SPA어플리케이션에서 사용하지 않음.
			.csrf(csrf -> csrf.disable())
			.exceptionHandling(e -> e
					.authenticationEntryPoint((req,res,ex)->{
						// 인증 실패시 401처리
						res.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UNATUHORIZED");
					}).accessDeniedHandler((req,res,ex)->{
						// 인증 실패시 403처리
						res.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UNATUHORIZED");
					}))
			
			// 서버에서 인증상태를 관리하지 않게 하는 설정
			.sessionManagement(
					management-> 
					management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			
			.oauth2Login(oauth -> oauth
					// 인증정보를 바탕으로 자동 회원가입
					// 요청처리 완료후, accesToken과 refreshToken을 사용자에게 전달.
					.userInfoEndpoint(u -> u.userService(oauth2Service))
					.successHandler(oauth2SuccessHandler)
					)
			.authorizeHttpRequests(auth ->
				auth
				.requestMatchers("/auth/login","/auth/signUp","/auth/logout","/auth/refresh").permitAll()
				.requestMatchers("/","/oauth2/**","/login**","/error").permitAll()
				
				.requestMatchers("/**").authenticated()
			);
		http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
		
		
		return http.build();
	}
	
	//CORS 설정정보를 가진 빈객체
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		
		// 허용 Origin설정
		config.setAllowedOrigins(List.of("http://localhost:5173"));
		
		// 허용 메서드
		config.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE"));
		config.setAllowedHeaders(List.of("*"));
		config.setExposedHeaders(List.of("Location","Authorization"));
		config.setAllowCredentials(true); // 세션,쿠키 허용
		config.setMaxAge(3600L); //요청정보 캐싱시간
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		
		return source;		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}
	
	@Bean
	public RestTemplate restTemplate() {
		return new RestTemplate();
	}
	
	
}