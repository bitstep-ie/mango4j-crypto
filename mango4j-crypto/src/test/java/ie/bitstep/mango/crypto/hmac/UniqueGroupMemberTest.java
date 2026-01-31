package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.annotations.UniqueGroup;
import ie.bitstep.mango.crypto.hmac.UniqueGroupMember;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

public class UniqueGroupMemberTest {
	private static final String SOME_TEST_FIELD_WITH_UNIQUE_GROUP_ANNOTATION_FIELD_NAME = "someTestFieldWithUniqueGroupAnnotation";
	private static final String TEST_GROUP_NAME = "test-group";
	private static final int TEST_GROUP_ORDER = 1;

	@UniqueGroup(name = TEST_GROUP_NAME, order = TEST_GROUP_ORDER)
	private String someTestFieldWithUniqueGroupAnnotation;

	@Test
	void constructor() throws NoSuchFieldException {
		Field fieldWithUniqueGroupAnnotation = this.getClass().getDeclaredField(SOME_TEST_FIELD_WITH_UNIQUE_GROUP_ANNOTATION_FIELD_NAME);
		UniqueGroup uniqueGroupAnnotation = fieldWithUniqueGroupAnnotation.getDeclaredAnnotation(UniqueGroup.class);

		UniqueGroupMember uniqueGroupMember =
				new UniqueGroupMember(uniqueGroupAnnotation,
						fieldWithUniqueGroupAnnotation);

		assertThat(uniqueGroupMember.field()).isEqualTo(fieldWithUniqueGroupAnnotation);
		assertThat(uniqueGroupMember.uniqueGroup()).isEqualTo(uniqueGroupAnnotation);
	}
}
