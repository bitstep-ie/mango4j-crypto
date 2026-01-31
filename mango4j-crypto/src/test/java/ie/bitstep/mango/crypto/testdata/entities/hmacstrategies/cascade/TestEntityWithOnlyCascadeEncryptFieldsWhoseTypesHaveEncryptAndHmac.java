package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;

public class TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac {

	@CascadeEncrypt
	private TestMockHmacEntity testMockHmacEntity1;

	@CascadeEncrypt
	private TestMockHmacEntity testMockHmacEntity2;

	private TestMockHmacEntity testMockHmacEntity3NotTraversed;


}
