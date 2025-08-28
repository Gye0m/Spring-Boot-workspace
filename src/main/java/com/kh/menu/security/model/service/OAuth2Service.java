package com.kh.menu.security.model.service;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.kh.menu.security.model.dao.AuthDao;
import com.kh.menu.security.model.dto.AuthDto.User;
import com.kh.menu.security.model.dto.AuthDto.UserAuthority;
import com.kh.menu.security.model.dto.AuthDto.UserIdentities;
import com.kh.menu.security.model.dto.CustomOAuth2User;
import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class OAuth2Service implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	private final AuthDao authDao;
	/*
	 * 1.사용자 정보 로드 메서드
	 * - 인증 완료 후, Oauth2User객체를 전달받아 원하는 비지니스 로직을 처리하기 위해 사용한다.
	 * - db에서 사용자정보 조회 후, 존재하지 않는 사용자라면 자동 회원가입
	 * */
	@Override
	@Transactional
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
		Map<String,Object> attributes = oAuth2User.getAttributes();
		
		String provider = userRequest.getClientRegistration().getRegistrationId();
		String providerUserId = String.valueOf(attributes.get("id"));
		String accessToken = userRequest.getAccessToken().getTokenValue();
		if(provider.equals("kakao")) {
			Map<String,Object> kakaoAccount = (Map<String,Object>)attributes.get("kakao_account");
			String email = (String) kakaoAccount.get("email");
			Map<String, Object> profile = (Map<String,Object>) kakaoAccount.get("profile");
			
			//데이터 베이스에서 회원정보 조회
			User user = authDao.findUserByEmail(email);
			if(user == null) {
				//새로운 사용자인 경우 자동 회원가입.
				user = User.builder()
						.email(email)
						.name((String)profile.get("nickname"))
						.profile((String) profile.get("profile_image_url"))
						.build();
				authDao.insertUser(user);
				
				//유저 소셜정보
				UserIdentities userIdentities = UserIdentities.builder()
						.provider(provider)
						.providerUserId(providerUserId)
						.accessToken(accessToken)
						.userId(user.getId())
						.build();
				authDao.insertUserIdentities(userIdentities);
				
				UserAuthority auth = UserAuthority.builder()
						.userId(user.getId())
						.roles(List.of("ROLE_USER"))
						.build();
				authDao.insertUserRole(auth);
			}
			//이미 회원가입은 했지만 다시 로그인한 경우
			//accessToken 업데이트
			UserIdentities userIdentities = UserIdentities.builder()
					.provider(provider)
					.providerUserId(providerUserId)
					.accessToken(accessToken)
					.build();
			authDao.updateUserIdentities(userIdentities);
			
			return new CustomOAuth2User(null, attributes, "id", user.getId());
		}
		
		return new DefaultOAuth2User(oAuth2User.getAuthorities(), attributes, "id");
				
		
	}
}