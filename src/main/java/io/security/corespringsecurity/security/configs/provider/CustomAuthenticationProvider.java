package io.security.corespringsecurity.security.configs.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.configs.service.impl.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {
	@Autowired
	UserDetailsService userDetailsService;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		//사용자가 입력한 값들
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();

		AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

		if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword())) {
			throw new BadCredentialsException("올바른 패스워드가 아닙니다!");
		}

		FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();

		if(formWebAuthenticationDetails.getSecretKey() == null || !"secret".equals(formWebAuthenticationDetails.getSecretKey())) {
			throw new InsufficientAuthenticationException("시크릿 키가 없음!");
		}

		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

		return authenticationToken;
	}

	@Override
	public boolean supports(Class<?> aClass) {
		// 토큰이 현재 파라미터로 전달된 이 클래스의 타입과 일치할 때, 이 클래스가 인증처리를 한다.
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
	}
}
