package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		String errorMassage = "인증 실패!!!!!!";

		if(exception instanceof BadCredentialsException) {
			errorMassage += " 아이디와 비밀번호를 확인하세요.";
		} else if (exception instanceof InsufficientAuthenticationException) {
			errorMassage += " 시크릿 키가 존재하지 않습니다.";
		}

		setDefaultFailureUrl("/login?error=true&exception=" + errorMassage); // Spring Boot는 해당 String을 모두 url로 인식하기 때문에 접근 관련 설정에서 접근가능하도록 변경해야 한다.

		super.onAuthenticationFailure(request, response, exception);
	}
}
