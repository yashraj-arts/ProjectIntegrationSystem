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
public class PostHttpMethodSecurityService implements HttpMethodSecurityService {
	private static final Logger LOGGER = LogManager.getLogger(PostHttpMethodSecurityService.class);

	@Value("${payment.signatureKey}")
	private String signatureKey;

	@Override
	public boolean validate(WrappedRequest request, String signature) {
		try {
			String message = request.getBody();

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
