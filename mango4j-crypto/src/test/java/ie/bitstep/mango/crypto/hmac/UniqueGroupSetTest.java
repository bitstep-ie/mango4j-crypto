package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.annotations.UniqueGroup;
import ie.bitstep.mango.crypto.hmac.UniqueGroupSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class UniqueGroupSetTest {
	private static final String FIELD_NAME_1 = "field1";
	private static final String FIELD_NAME_2 = "field2";
	private static final String TEST_GROUP_NAME = "test-group";
	private static final int FIELD_NAME_1_TEST_GROUP_ORDER = 1;
	private static final int FIELD_NAME_2_TEST_GROUP_ORDER = 2;

	@UniqueGroup(name = TEST_GROUP_NAME, order = FIELD_NAME_1_TEST_GROUP_ORDER)
	private String field1;

	@UniqueGroup(name = TEST_GROUP_NAME, order = FIELD_NAME_2_TEST_GROUP_ORDER)
	private String field2;


	private Field field1Reference;
	private Field field2Reference;
	private UniqueGroup field1UniqueGroupAnnotation;
	private UniqueGroup field2UniqueGroupAnnotation;
	private UniqueGroupSet uniqueGroupSet;

	@Test
	void copyingConstructor() {
		uniqueGroupSet.addAll(Set.of(field1Reference, field2Reference));

		UniqueGroupSet newUniqueGroupSet = new UniqueGroupSet(uniqueGroupSet);

		assertThat(newUniqueGroupSet.contains(field1Reference)).isTrue();
		assertThat(newUniqueGroupSet.contains(field2Reference)).isTrue();
		assertThat(newUniqueGroupSet.isEmpty()).isFalse();
		assertThat(newUniqueGroupSet.getGroups()).hasSize(1);
		assertThat(newUniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).hasSize(2);
		assertThat(newUniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field1Reference);
		assertThat(newUniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field2Reference);
		assertThat(newUniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers()).hasSize(2);
		assertThat(newUniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers())
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field1Reference)
						&& uniqueGroupWrapper.uniqueGroup().equals(field1UniqueGroupAnnotation))
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field2Reference)
						&& uniqueGroupWrapper.uniqueGroup().equals(field2UniqueGroupAnnotation));
	}

	@BeforeEach
	void setup() throws NoSuchFieldException {
		field1Reference = this.getClass().getDeclaredField(FIELD_NAME_1);
		field1UniqueGroupAnnotation = field1Reference.getAnnotation(UniqueGroup.class);
		field2Reference = this.getClass().getDeclaredField(FIELD_NAME_2);
		field2UniqueGroupAnnotation = field2Reference.getAnnotation(UniqueGroup.class);
		uniqueGroupSet = new UniqueGroupSet();
	}

	@Test
	void add() {
		uniqueGroupSet.add(field1Reference);

		assertThat(uniqueGroupSet.contains(field1Reference)).isTrue();
		assertThat(uniqueGroupSet.isEmpty()).isFalse();
		assertThat(uniqueGroupSet.getGroups()).hasSize(1);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).hasSize(1);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field1Reference);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers()).hasSize(1);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers())
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field1Reference))
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.uniqueGroup().equals(field1UniqueGroupAnnotation));
	}

	@Test
	void addSecondGroupMember() {
		uniqueGroupSet.add(field1Reference);
		uniqueGroupSet.add(field2Reference);

		assertThat(uniqueGroupSet.contains(field1Reference)).isTrue();
		assertThat(uniqueGroupSet.contains(field2Reference)).isTrue();
		assertThat(uniqueGroupSet.isEmpty()).isFalse();
		assertThat(uniqueGroupSet.getGroups()).hasSize(1);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).hasSize(2);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field1Reference);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field2Reference);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers()).hasSize(2);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers())
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field1Reference)
						&& uniqueGroupWrapper.uniqueGroup().equals(field1UniqueGroupAnnotation))
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field2Reference)
						&& uniqueGroupWrapper.uniqueGroup().equals(field2UniqueGroupAnnotation));
	}

	@Test
	void addAll() {
		uniqueGroupSet.addAll(Set.of(field1Reference, field2Reference));

		assertThat(uniqueGroupSet.contains(field1Reference)).isTrue();
		assertThat(uniqueGroupSet.contains(field2Reference)).isTrue();
		assertThat(uniqueGroupSet.isEmpty()).isFalse();
		assertThat(uniqueGroupSet.getGroups()).hasSize(1);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).hasSize(2);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field1Reference);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getAllFields()).contains(field2Reference);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers()).hasSize(2);
		assertThat(uniqueGroupSet.getGroups().get(TEST_GROUP_NAME).getUniqueGroupWrappers())
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field1Reference)
						&& uniqueGroupWrapper.uniqueGroup().equals(field1UniqueGroupAnnotation))
				.anyMatch(uniqueGroupWrapper -> uniqueGroupWrapper.field().equals(field2Reference)
						&& uniqueGroupWrapper.uniqueGroup().equals(field2UniqueGroupAnnotation));
	}
}
