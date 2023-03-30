package io.security.corespringsecurity.security.configs.service.impl;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
public class CustomUserDetailServiceImpl implements UserDetailsService { //UserDetailsService를 구현하여 Custome한 서비스

	@Autowired
	private UserRepository userRepository; // DB에서 account객체를 조회하기 위한 repository 주입

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Account account = userRepository.findByUsername(username);

		if(account == null) {
			throw new UsernameNotFoundException("해당하는 계정이 존재하지 않습니다.");
		}

		//권한 부여를 위한 List 생성
		List<GrantedAuthority> roles = new ArrayList<>();
		roles.add(new SimpleGrantedAuthority(account.getRole()));   // DB에 저장한 권한을 조회하여 설정

		return new AccountContext(account, roles);
	}
}
