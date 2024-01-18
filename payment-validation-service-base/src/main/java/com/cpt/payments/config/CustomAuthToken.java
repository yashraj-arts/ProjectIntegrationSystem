package com.cpt.payments.config;

import java.util.Arrays;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class CustomAuthToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -9130736304913494541L;

	public CustomAuthToken() {
		super(Arrays.asList());
		super.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
	}

}
