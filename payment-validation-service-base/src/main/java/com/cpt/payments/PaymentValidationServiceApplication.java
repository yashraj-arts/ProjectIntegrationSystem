package com.cpt.payments;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(scanBasePackages = { "com.cpt.payments" },exclude = {UserDetailsServiceAutoConfiguration.class })
@EnableAsync
@EnableScheduling
public class PaymentValidationServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(PaymentValidationServiceApplication.class, args);
		System.out.println("application started");
	}

}
