package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;

public class TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyEncrypt {

	@CascadeEncrypt
	private TestAnnotatedEntityNoHmacFields testAnnotatedEntityNoHmacFields1;

	@CascadeEncrypt
	private TestAnnotatedEntityNoHmacFields testAnnotatedEntityNoHmacFields2;

	private TestAnnotatedEntityNoHmacFields testMockHmacEntity3testAnnotatedEntityNoHmacFieldsNotTraversed;


}
