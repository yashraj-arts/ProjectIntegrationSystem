package com.cpt.payments.security.service;

import com.cpt.payments.constants.WrappedRequest;

public interface HttpMethodSecurityService {

	boolean validate(WrappedRequest request, String signature);

}
