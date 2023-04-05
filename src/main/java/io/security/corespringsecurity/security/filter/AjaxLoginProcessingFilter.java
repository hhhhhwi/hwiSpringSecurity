package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
	private static final String X_REQUESTED_WITH = "X-Requested-With";

	private ObjectMapper objectMapper = new ObjectMapper();

	public AjaxLoginProcessingFilter() {
		super(new AntPathRequestMatcher("/api/login")); // 위 url에 대해 filter가 요청을 처리하도록 설정
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
		if(!isAjax(httpServletRequest)) {
			throw new IllegalStateException("인증처리가 지원되지 않습니다.");
		}

		AccountDto accountDto = objectMapper.readValue(httpServletRequest.getReader(), AccountDto.class); //json 방식을 AccountDto객체로 변환

		if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
			throw new IllegalArgumentException("Username이나 Password이 입력되지 않았습니다.");
		}

		AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());

		return this.getAuthenticationManager().authenticate(authenticationToken);
	}

	private boolean isAjax(HttpServletRequest httpServletRequest) {
		// 사용자의 요청이 ajax 방식인지
		// 사용자의 요청에 Header에 담긴 값과 서버에서 정한 값이 같은 지를 판단단
		return XML_HTTP_REQUEST.equals(httpServletRequest.getHeader(X_REQUESTED_WITH));
	}
}
