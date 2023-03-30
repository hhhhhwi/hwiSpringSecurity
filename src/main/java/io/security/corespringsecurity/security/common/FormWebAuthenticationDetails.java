package io.security.corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

// 이건 왜 extends 했을까?
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

	private String secretKey;

	public FormWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
		secretKey = request.getParameter("secretKey");
	}

	public String getSecretKey() {
		return secretKey;
	}
}
