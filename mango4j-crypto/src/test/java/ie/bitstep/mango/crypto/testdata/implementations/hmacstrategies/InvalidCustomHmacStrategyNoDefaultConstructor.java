package ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies;

import ie.bitstep.mango.crypto.hmac.HmacStrategy;

public class InvalidCustomHmacStrategyNoDefaultConstructor implements HmacStrategy {

	public InvalidCustomHmacStrategyNoDefaultConstructor(String testValue) {
	}

	@Override
	public void hmac(Object entity) {

	}
}
