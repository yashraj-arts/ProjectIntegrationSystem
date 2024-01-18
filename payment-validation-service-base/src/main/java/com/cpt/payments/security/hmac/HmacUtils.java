package com.cpt.payments.security.hmac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;

import com.cpt.payments.constants.ErrorCodeEnum;
import com.cpt.payments.exceptions.ValidationException;
import com.cpt.payments.pojo.Payment;
import com.cpt.payments.pojo.PaymentRequest;
import com.cpt.payments.pojo.User;
import com.cpt.payments.util.LogMessage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

public final class HmacUtils {

	private static final Logger LOGGER = LogManager.getLogger(HmacUtils.class);

	public static final String HEX_ARRAY = "0123456789abcdef";

	public static boolean sign(String secret, String signature, String message) {

		return hmacSha256(secret, message, signature);
	}

	private static boolean hmacSha256(String secret, String message, String signature) {

		byte[] secretKeyBytes = secret.getBytes();

		String messageDigest = generateHmac256(message, secretKeyBytes);
		if (!messageDigest.equals(signature)) {
			LogMessage.log(LOGGER, "signature is not matched. payment request is altered");
			LogMessage.log(LOGGER, "messageDigest ::" + messageDigest + " , signature :: " + signature);

			return false;
		}
		LogMessage.log(LOGGER, "signature matched. payment request is proper");
		return true;
	}

	private static String generateHmac256(String message, byte[] key) {
		ObjectMapper objectMapper = new ObjectMapper();
		JsonNode jsonNode;
		String response;
		try {
			try {
				jsonNode = objectMapper.readValue(message, JsonNode.class);
				response = jsonNode.toString();
			} catch (Exception e) {
				response = message;
				LogMessage.log(LOGGER, "Exception converting to JSON, using plain message for Sig Generation");
			}
			
			LogMessage.log(LOGGER, ":: message string is :: " + response);
			byte[] bytes = hmac(key, response.getBytes());
			return bytesToHex(bytes);
		} catch (Exception e) {
			LogMessage.log(LOGGER, "Exception in generateHmac256" + e);
			throw new ValidationException(HttpStatus.UNAUTHORIZED, ErrorCodeEnum.SIGNATURE_ALTERED.getErrorCode(),
					ErrorCodeEnum.SIGNATURE_ALTERED.getErrorMessage());
		}
	}

	private static byte[] hmac(byte[] key, byte[] message) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			return mac.doFinal(message);
		} catch (Exception e) {
			LogMessage.log(LOGGER, "Exception in generateHmac256" + e);
			throw new ValidationException(HttpStatus.UNAUTHORIZED, ErrorCodeEnum.SIGNATURE_ALTERED.getErrorCode(),
					ErrorCodeEnum.SIGNATURE_ALTERED.getErrorMessage());
		}

	}

	private static String bytesToHex(byte[] bytes) {
		final char[] hexArray = HEX_ARRAY.toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0, v; j < bytes.length; j++) {
			v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static void main(String[] args) {
		Gson gson = new Gson();
		
		/*
		  {
    
    "payment": {
        "paymentMethod": "APM",
        "paymentType": "SALE",
        "amount": "18.00",
        "currency": "EUR",
        "merchantTransactionReference": "ct_test107",
        "providerId": "Trustly",
        "creditorAccount": "4242424242424242",
        "debitorAccount": "4111111111111111"
    }
}

		 */
		
		PaymentRequest req = new PaymentRequest();
		Payment payment = new Payment();
		payment.setPaymentMethod("APM");
		payment.setPaymentType("SALE");
		payment.setAmount("18.00");
		payment.setCurrency("EUR");
		payment.setMerchantTransactionReference("ct_test114");
		payment.setProviderId("Trustly");

		payment.setCreditorAccount("4242424242424242");
		payment.setDebitorAccount("4111111111111111");
		
		req.setPayment(payment);
		
		
		/*
		 "user": {
        "firstName": "john",
        "lastName": "peter",
        "email": "johnpeter@gmail.com",
        "phoneNumber": "+919393939393"
    }, 
		 */
		User user = new User();
		user.setEmail("johnpeter@gmail.com");
		user.setFirstName("john");
		user.setLastName("peter");
		user.setPhoneNumber("+919393939393");
		
		req.setUser(user);
		
		//String jsonReq = gson.toJson(req);
		String jsonReq = "/payments/add?num1=4&num2=8";
		
		String secret = "cptTraining";
		byte[] signatureKeyBytes = secret.getBytes();
		
		String messageDigest = generateHmac256(jsonReq, signatureKeyBytes);
		System.out.println("Generated Sig:" + messageDigest);
	}
}