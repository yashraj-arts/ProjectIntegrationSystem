package com.cpt.payments.security.hmac;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.cpt.payments.constants.ErrorCodeEnum;
import com.cpt.payments.constants.WrappedRequest;
import com.cpt.payments.exceptions.ValidationException;
import com.cpt.payments.security.service.HttpMethodSecurityService;
import com.cpt.payments.security.service.impl.GetHttpMethodSecurityService;
import com.cpt.payments.security.service.impl.PostHttpMethodSecurityService;
import com.cpt.payments.util.LogMessage;

@Component
public class HmacSecurityProvider {

	private static final String GET = "GET";

	private static final String POST = "POST";

	private static final Logger LOGGER = LogManager.getLogger(HmacSecurityProvider.class);

	@Autowired
	private ApplicationContext context;

	public boolean verifyHmac(WrappedRequest request) {
		String signature = request.getHeader("signature");

		if (null == signature) {
			LogMessage.log(LOGGER, ">> Signature is null " + signature);
			throw new ValidationException(HttpStatus.UNAUTHORIZED, ErrorCodeEnum.SIGNATURE_NOT_FOUND.getErrorCode(),
					ErrorCodeEnum.SIGNATURE_NOT_FOUND.getErrorMessage());
		}

		String httpMethod = request.getMethod();

		HttpMethodSecurityService httpMethodSecurityService = getHttpMethodSecurityService(httpMethod);
		if (null == httpMethodSecurityService) {
			LogMessage.log(LOGGER, ">> httpMethod not supported " + httpMethod);
			throw new ValidationException(HttpStatus.UNAUTHORIZED,
					ErrorCodeEnum.HTTP_METHOD_NOT_SUPPORTED.getErrorCode(),
					ErrorCodeEnum.HTTP_METHOD_NOT_SUPPORTED.getErrorMessage());
		}

		try {
			boolean signatureStatus = httpMethodSecurityService.validate(request, signature);
			LogMessage.log(LOGGER, ">> verifySignatureStatus is  " + signatureStatus);
			if (signatureStatus) {
				return true;
			} else {
				throw new ValidationException(HttpStatus.UNAUTHORIZED, ErrorCodeEnum.SIGNATURE_ALTERED.getErrorCode(),
						ErrorCodeEnum.SIGNATURE_ALTERED.getErrorMessage());
			}
		} catch (Exception e) {
			LogMessage.log(LOGGER, "Exception in generateHmac256" + e);
			throw new ValidationException(HttpStatus.UNAUTHORIZED, ErrorCodeEnum.SIGNATURE_ALTERED.getErrorCode(),
					ErrorCodeEnum.SIGNATURE_ALTERED.getErrorMessage());
		}

	}

	private HttpMethodSecurityService getHttpMethodSecurityService(String httpMethod) {
		LogMessage.log(LOGGER, ">> httpMethod is  " + httpMethod);
		if (null == httpMethod) {
			LogMessage.log(LOGGER, ">> httpMethod is null " + httpMethod);
			throw new ValidationException(HttpStatus.UNAUTHORIZED, ErrorCodeEnum.HTTP_METHOD_NOT_FOUND.getErrorCode(),
					ErrorCodeEnum.HTTP_METHOD_NOT_FOUND.getErrorMessage());
		}

		switch (httpMethod) {
		case POST:
			return context.getBean(PostHttpMethodSecurityService.class);
		case GET:
			return context.getBean(GetHttpMethodSecurityService.class);
		default:
			return null;
		}
	}
}