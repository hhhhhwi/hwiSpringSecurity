package io.security.corespringsecurity.security.common;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * Custom한 WebAuthenticationDetails - 을 반환하기 윈한 서비스
 */
@Component //설정 클래스에서 추가를 해야되기 때문에 Bean으로 생성
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
	@Override
	public WebAuthenticationDetails buildDetails(HttpServletRequest httpServletRequest) {
		return new FormWebAuthenticationDetails(httpServletRequest);
	}
}
