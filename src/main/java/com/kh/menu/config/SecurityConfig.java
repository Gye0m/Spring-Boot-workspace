package com.kh.menu.config;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import lombok.RequiredArgsConstructor;
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		
		http
			//Cors관련 빈객체 등록
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			// CSRF는 SPA어플리케이션에서 사용하지 않음.
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests(auth ->
				auth.requestMatchers("/**").permitAll()
			);
		
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
		config.setExposedHeaders(List.of("Location"));
		config.setAllowCredentials(true); // 세션,쿠키 허용
		config.setMaxAge(3600L); //요청정보 캐싱시간
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		
		return source;		
	}
	
	
	
}