package io.security.corespringsecurity.security.configs.service.impl;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

// 왜 이름이 AccountContext일까?
public class AccountContext extends User {

	// 나중에 참조하기 위해 하나 만든다.
	private final Account account;

	public AccountContext(Account account,  Collection<? extends GrantedAuthority> authorities) {
		super(account.getUsername(), account.getPassword(), authorities);
		this.account = account;
	}

	public Account getAccount() {
		return account;
	}
}
