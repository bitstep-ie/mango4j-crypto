package ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;

public class MockHmacStrategyImpl implements HmacStrategy {
	public static Object entityPassedToHmac = null;
	public static Class<?> annotatedEntityClassPassedToConstructor = null;
	public static HmacStrategyHelper hmacStrategyHelperPassedToConstructor = null;


	public MockHmacStrategyImpl(Class<?> annotatedEntityClass, HmacStrategyHelper hmacStrategyHelper) {
		annotatedEntityClassPassedToConstructor = annotatedEntityClass;
		hmacStrategyHelperPassedToConstructor = hmacStrategyHelper;
	}

	@Override
	public void hmac(Object entity) {
		entityPassedToHmac = entity;
	}
}