package ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies;

import ie.bitstep.mango.crypto.hmac.HmacStrategy;

public class InvalidCustomHmacStrategyNoDefaultConstructor implements HmacStrategy {

	public InvalidCustomHmacStrategyNoDefaultConstructor(String testValue) {
		// Only used for testing purposes, not a valid HmacStrategy implementation as it does not have a default constructor
	}

	@Override
	public void hmac(Object entity) {
		// Only used for test validation, so can be left empty
	}
}
