package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;

public class TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyCollectionCascadeEncryptField {

	@CascadeEncrypt
	private TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields1;

	@CascadeEncrypt
	private TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields2;

	private TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields3NotTraversed; // NOSONAR - Need this field to test that only fields annotated with @CascadeEncrypt are traversed


}
