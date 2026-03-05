package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;
import ie.bitstep.mango.crypto.annotations.strategies.HmacStrategyToUse;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;

import java.util.List;

@HmacStrategyToUse("ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies.MockHmacStrategyImpl")
public class TestEntityWithCollectionCascadeEncryptFields {

	@CascadeEncrypt
	private List<TestMockHmacEntity> testMockHmacEntities;

	public List<TestMockHmacEntity> getTestMockHmacEntities() {
		return testMockHmacEntities;
	}

	public void setTestMockHmacEntities(List<TestMockHmacEntity> testMockHmacEntities) {
		this.testMockHmacEntities = testMockHmacEntities;
	}
}