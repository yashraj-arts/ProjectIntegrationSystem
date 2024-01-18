package com.cpt.payments.security.service.impl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.cpt.payments.constants.WrappedRequest;
import com.cpt.payments.security.hmac.HmacUtils;
import com.cpt.payments.security.service.HttpMethodSecurityService;
import com.cpt.payments.util.LogMessage;

@Component
public class GetHttpMethodSecurityService implements HttpMethodSecurityService {
	
	private static final Logger LOGGER = LogManager.getLogger(GetHttpMethodSecurityService.class);

	@Value("${payment.signatureKey}")
	private String signatureKey;


	@Override
	public boolean validate(WrappedRequest request, String signature) {
		LogMessage.log(LOGGER, ">> requestUri is  " + request.getRequestURI());
		try {
			/*
			 * If we have requestParams then add those params to message for signature calculations.
			 */
			String message = request.getRequestURI();

			// Digest are calculated using a public shared secret
			boolean verifySignatureStatus = HmacUtils.sign(signatureKey, signature, message);
			LogMessage.log(LOGGER, ">> verifySignatureStatus is  " + verifySignatureStatus);
			if (verifySignatureStatus) {
				return true;
			} else {
				return false;
			}
		} catch (Exception e) {
			LogMessage.log(LOGGER, "Exception in generateHmac256" + e);
			return false;
		}
	}


}
