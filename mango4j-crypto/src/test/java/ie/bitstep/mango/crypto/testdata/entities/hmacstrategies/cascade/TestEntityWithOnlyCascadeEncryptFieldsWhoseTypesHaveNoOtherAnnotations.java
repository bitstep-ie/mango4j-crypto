package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.NothingAnnotatedEntity;

public class TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveNoOtherAnnotations {

	@CascadeEncrypt
	private NothingAnnotatedEntity nothingAnnotatedEntity1;

	@CascadeEncrypt
	private NothingAnnotatedEntity nothingAnnotatedEntity2;

	private NothingAnnotatedEntity nothingAnnotatedEntityNotTraversed;
}
