package com.cpt.payments.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cpt.payments.security.ExceptionHandlerFilter;
import com.cpt.payments.security.hmac.HmacFilter;
import com.cpt.payments.security.hmac.HmacSecurityProvider;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	private final HmacSecurityProvider hmacSecurityProvider;

	public SecurityConfiguration(HmacSecurityProvider hmacSecurityProvider) {
		this.hmacSecurityProvider = hmacSecurityProvider;
	}

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		
		//.headers().frameOptions().disable()
		
		http.csrf().disable()
				.authorizeRequests()
				
				//.anyRequest().authenticated()
				.anyRequest().permitAll()

				.and()
				/*
				.addFilterBefore(new ExceptionHandlerFilter(), UsernamePasswordAuthenticationFilter.class)
				.addFilterAfter(new HmacFilter(hmacSecurityProvider), UsernamePasswordAuthenticationFilter.class)
				*/
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		 
		return http.build();
	}
	
}
