package ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;

public class HmacStrategyExceptionThrowingConstructor implements HmacStrategy {

	@Hmac
	private String value;

	public HmacStrategyExceptionThrowingConstructor(Class<?> entityClass, HmacStrategyHelper hmacStrategyHelper) {
		throw new RuntimeException();
	}

	@Override
	public void hmac(Object entity) {

	}
}
