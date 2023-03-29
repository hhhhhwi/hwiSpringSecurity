package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.configs.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/api/**") // api 로 시작하는 요청에 대해서만 ajaxSecurityConfig가 동작하도록
				.authorizeRequests()
				.anyRequest().authenticated()
		.and()
				.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class) // 기존의 필터 앞에 위치하여 인증처리
		;

		http.csrf().disable();
	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(customAuthenticationProvider());
	}

	@Bean
	public CustomAuthenticationProvider customAuthenticationProvider() {
		return new CustomAuthenticationProvider();
	}

	@Bean
	public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
		AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
		ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean()); // 매니저를 설정해줘야 한다.

		return ajaxLoginProcessingFilter;
	}
}
