package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.annotations.UniqueGroup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class UniqueGroupTest {
	private static final String SOME_TEST_FIELD_WITHOUT_UNIQUE_GROUP_ANNOTATION_FIELD_NAME = "someTestFieldWithoutUniqueGroupAnnotation";
	private static final String SOME_TEST_FIELD_WITH_UNIQUE_GROUP_ANNOTATION_FIELD_NAME = "someTestFieldWithUniqueGroupAnnotation";
	private static final String TEST_GROUP_NAME = "test-group";
	private static final int TEST_GROUP_ORDER = 1;

	private String someTestFieldWithoutUniqueGroupAnnotation;

	@UniqueGroup(name = TEST_GROUP_NAME, order = TEST_GROUP_ORDER)
	private String someTestFieldWithUniqueGroupAnnotation;

	private Field fieldWithoutUniqueGroupAnnotation;
	private Field fieldWithUniqueGroupAnnotation;
	private ie.bitstep.mango.crypto.hmac.UniqueGroup uniqueGroup;

	@BeforeEach
	void setup() throws NoSuchFieldException {
		uniqueGroup = new ie.bitstep.mango.crypto.hmac.UniqueGroup();
		fieldWithoutUniqueGroupAnnotation = UniqueGroupTest.class.getDeclaredField(SOME_TEST_FIELD_WITHOUT_UNIQUE_GROUP_ANNOTATION_FIELD_NAME);
		fieldWithUniqueGroupAnnotation = UniqueGroupTest.class.getDeclaredField(SOME_TEST_FIELD_WITH_UNIQUE_GROUP_ANNOTATION_FIELD_NAME);
	}

	@Test
	void constructor() {
		assertThat(uniqueGroup.getUniqueGroupWrappers()).isEmpty();
		assertThat(uniqueGroup.getAllFields()).isEmpty();
	}

	@Test
	void addFieldWithoutUniqueGroupAnnotation() {
		assertThatThrownBy(() -> uniqueGroup.add(fieldWithoutUniqueGroupAnnotation))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'someTestFieldWithoutUniqueGroupAnnotation' has no associated UniqueGroup annotation");
	}

	@Test
	void addFieldWithUniqueGroupAnnotation() {
		uniqueGroup.add(fieldWithUniqueGroupAnnotation);

		assertThat(uniqueGroup.getUniqueGroupWrappers()).hasSize(TEST_GROUP_ORDER);
		assertThat(uniqueGroup.getUniqueGroupWrappers())
				.anyMatch(uniqueGroupWrapper ->
						uniqueGroupWrapper.field().equals(fieldWithUniqueGroupAnnotation)
								&& uniqueGroupWrapper.uniqueGroup().name().equals(TEST_GROUP_NAME)
								&& uniqueGroupWrapper.uniqueGroup().order() == 1 && !uniqueGroupWrapper.uniqueGroup().isOptional());
		assertThat(uniqueGroup.getAllFields()).hasSize(1)
				.anyMatch(field -> field.equals(fieldWithUniqueGroupAnnotation));
	}
}
