package com.cpt.payments.security.hmac;

import java.io.IOException;



import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.cpt.payments.config.CustomAuthToken;
import com.cpt.payments.constants.WrappedRequest;
import com.cpt.payments.util.LogMessage;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class HmacFilter extends OncePerRequestFilter {

	private static final Logger LOGGER = LogManager.getLogger(HmacFilter.class);
	private final HmacSecurityProvider hmacSecurityProvider;

	public HmacFilter(HmacSecurityProvider hmacSecurityProvider) {
		this.hmacSecurityProvider = hmacSecurityProvider;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			FilterChain filterChain) throws ServletException, IOException {

		WrappedRequest wrappedRequest = new WrappedRequest(servletRequest);

		LogMessage.log(LOGGER,">> request method is :: "+wrappedRequest.getMethod());

		LogMessage.log(LOGGER, ">> in HmacFilter ");
		if (hmacSecurityProvider.verifyHmac(wrappedRequest)) {
			LogMessage.log(LOGGER, ">> in HmacFilter >> signature verified and proceeding further");

			Authentication auth = new CustomAuthToken();
			SecurityContextHolder.getContext().setAuthentication(auth);

			LogMessage.log(LOGGER, " HmacFilter Before doFilter");
			filterChain.doFilter(wrappedRequest, servletResponse);
			LogMessage.log(LOGGER, " HmacFilter After doFilter");
		}
	}
}