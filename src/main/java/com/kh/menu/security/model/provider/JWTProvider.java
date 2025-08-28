package com.kh.menu.security.model.provider;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/*
 * #1. JWT
 *  - JSON형식의 데이터를 서명을 통해 위변조를 방지한 토큰으로, 인증 및 인가에 사용
 *  - REST API서버는 제약조건상 무상태 서버로 설계되어 사용자의 인증정보를 서버세션에
 *    저장하지 않고, 클라이언트에게 인증정보(JWT)를 저장시킨다.
 *  - 발급된 JWT토큰은 클라이언트가 매 요청시 함께 전달하여, 인증에 사용한다.
 *  
 * #2. JWT토큰을 활용한 인증/인가 매커니즘
 *  1. 사용자가 아이디와 비밀번호로 로그인 요청을 보낸다.
 *  2. 서버는 사용자 정보를 확인한 뒤, JWT토큰을 생성하여 클라이언트에게 전달한다.
 *  3. 클라이언트는 이 토큰을 LocalStorage 혹은 Cookie에 저장한다.
 *  4. 이후 API요청 시 클라이언트는 요청 헤더에 토큰을 포함하여 전송한다.
 *  5. 서버는 토큰의 서명과 만료시간을 검증하여 유효하다면 요청을 처리한다. 
 *  6. 토큰이 만료된 경우 클라이언트는 재로그인을 통해 토큰을 재발급한다.
 *  
 * #3. JWT토큰 구조
 *  - 헤더 : 토큰의 타입과 서명에 사용한 알고리즘의 정보를 포함
 *  - 페이로드 : 토큰의 내용(클레임)이 포함된다.
 *  		   내용으로는 sub(사용자 id), exp(만료시간), etc등이 포함된다.
 *  - 서명 : 헤더와 페이로드를 조합하여 암호환 값
 * 
 * #4. 주의사항
 *  - 토큰은 브라우저에 저장되므로, 토큰 탈취 위험이 존재한다. 탈취 당하는 경우를 대비해
 *    만료시간은 짧게 설정하는 게 좋다.
 *  - 토큰의 페이로드에는 민감한 개인정보를 저장하면 안된다.
 * */

@Component
public class JWTProvider {

	private final Key key;
	private final Key refreshKey;

	public JWTProvider(
			@Value("${jwt.secret}") 
			String secretBase64,
			@Value("${jwt.refresh-secret}") 
			String refreshSecretBase64
			) { // 토큰 서명에 사용하는 키값.
		byte[] keyBytes = Decoders.BASE64.decode(secretBase64);
		this.key = Keys.hmacShaKeyFor(keyBytes);
		this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecretBase64));
	}

	public String createAccessToken(Long id, int minutes) {
		Date now = new Date();
		return Jwts.builder().setSubject(String.valueOf(id)) // sub는 곧 아이디
				.setIssuedAt(now) // 토큰 발행시간
				.setExpiration(new Date(now.getTime() + (1000L * 60 * minutes))) // 만료 시간
				.signWith(key, SignatureAlgorithm.HS256) // 서명에 사용할 키값과 알고리즘
				.compact();
	}

	/*
	 * Refresh Token
	 *  - 유효시간이 짧은 Access Token을 새로 갱신받기 위한 용도의 토큰.
	 *  - Access Token보다 훨씬 긴 유효시간을 가지고 있다.
	 * */
	public String createRefreshToken(Long id, int i) {
		Date now = new Date();
		return Jwts.builder().setSubject(String.valueOf(id)) // 페이로드에 저장할 id
				.setIssuedAt(now) // 토큰 발행시간
				.setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * i))) // 만료 시간
				.signWith(refreshKey, SignatureAlgorithm.HS256) // 서명에 사용할 키값과 알고리즘
				.compact();
	}
	
	public long getUserId(String token) {
		return Long.valueOf(
				Jwts.parserBuilder()
					.setSigningKey(key)
					.build()
					.parseClaimsJws(token)
					.getBody()
					.getSubject()
				);
	}
	
	public Long parseRefresh(String token) {
		return Long.valueOf(
				Jwts.parserBuilder()
					.setSigningKey(refreshKey)
					.build()
					.parseClaimsJws(token)
					.getBody()
					.getSubject()
				);
	}
}