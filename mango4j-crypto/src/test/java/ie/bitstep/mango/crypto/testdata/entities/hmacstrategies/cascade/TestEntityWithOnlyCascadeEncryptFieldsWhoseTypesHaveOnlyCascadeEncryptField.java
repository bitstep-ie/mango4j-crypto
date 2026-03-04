package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;

public class TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyCascadeEncryptField {

	@CascadeEncrypt
	private TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac testMockHmacEntity1;

	@CascadeEncrypt
	private TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac testMockHmacEntity2;

	private TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac testMockHmacEntity3NotTraversed; // NOSONAR - Need this field to test that only fields annotated with @CascadeEncrypt are traversed


}
