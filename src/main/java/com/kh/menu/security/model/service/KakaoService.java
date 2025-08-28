package com.kh.menu.security.model.service;
import java.util.Map;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class KakaoService {
	
	private final RestTemplate restTemplate;
	
	/*
	 * 카카오 액서스 토큰으로 유저 정보를 조회
	 */
	
	public Map<String, Object> getUserInfo(String accessToken){
		String url = "https://kapi.kakao.com/v2/user/me";
		
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		
		HttpEntity<String> entity = new HttpEntity<>(headers);
		
		ResponseEntity<Map> response = restTemplate
				.exchange(url, HttpMethod.GET, entity, Map.class);
		
		return response.getBody();
	}
	/**
	 * 카카오 엑서스 토큰을 만료처리 하는 메서드
	 */
	public void logout(String kakaoAccessToken) {
		String url = "https://kapi.kakao.com/v1/user/logout";
		
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(kakaoAccessToken);
		
		HttpEntity<String> entity = new HttpEntity<>(headers);
		
		restTemplate.postForObject(url, entity, String.class);
	}
}