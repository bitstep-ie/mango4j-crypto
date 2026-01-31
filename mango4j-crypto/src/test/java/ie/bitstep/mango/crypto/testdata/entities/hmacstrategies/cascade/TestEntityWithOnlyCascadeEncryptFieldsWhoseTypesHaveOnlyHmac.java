package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntityWithNoEncryptFields;

public class TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyHmac {

	@CascadeEncrypt
	private TestMockHmacEntityWithNoEncryptFields testMockHmacEntityWithNoEncryptFields1;

	@CascadeEncrypt
	private TestMockHmacEntityWithNoEncryptFields testMockHmacEntityWithNoEncryptFields2;

	private TestMockHmacEntityWithNoEncryptFields testMockHmacEntityWithNoEncryptFieldsNotTraversed;


}
