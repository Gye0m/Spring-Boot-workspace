package com.kh.menu;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
 * @SpringBootApplication 내부 어노테이션들
 * 
 * 1. SpringBootConfiguration
 *  - springBoot 설정 파일임을 의미
 * 2. EnableAutoConfiguration
 *  - 자동설정활성화 어노테이션
 * 3. Component-Scan
 *  - 현재 실행된 클래스를 기준으로 하위 패키지의 모든 클래스를 검사하여
 *    빈객체로 등록해주는 어노테이션 
 *  */
@SpringBootApplication
public class MenuApplication {

	public static void main(String[] args) {
		SpringApplication.run(MenuApplication.class, args);
	}

}
