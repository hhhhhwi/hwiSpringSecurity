package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // passwordEncoder를 통해 암호화한 방식으로 전달
        String password = passwordEncoder().encode("1111");

        //인메모리 방식으로 사용자 생성. 권한 부여.
        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");
    }

    @Bean   //passwordEncoder는 빈으로 등록
    public PasswordEncoder passwordEncoder() {
        //평문인 password를 암호화처리
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                // 페이지별 권한 매칭
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
        ;

    }
}
