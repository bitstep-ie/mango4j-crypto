package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

class UniqueGroup {
	private final Set<UniqueGroupMember> uniqueGroupMembers = new TreeSet<>(Comparator.naturalOrder());
	private final List<Field> allUniqueGroupFields = new ArrayList<>();

	/**
	 * Adds a field to the unique group.
	 *
	 * @param field the field to add
	 */
	void add(Field field) {
		ie.bitstep.mango.crypto.annotations.UniqueGroup uniqueGroup = field.getAnnotation(ie.bitstep.mango.crypto.annotations.UniqueGroup.class);
		if (uniqueGroup == null) {
			throw new NonTransientCryptoException(
				String.format("Field '%s' has no associated %s annotation", field.getName(), ie.bitstep.mango.crypto.annotations.UniqueGroup.class.getSimpleName()));
		}
		allUniqueGroupFields.add(field);
		uniqueGroupMembers.add(new UniqueGroupMember(uniqueGroup, field));
	}

	/**
	 * Returns all fields participating in the unique group.
	 *
	 * @return the list of fields
	 */
	public List<Field> getAllFields() {
		return allUniqueGroupFields;
	}

	/**
	 * Returns an ordered set of group members sorted by {@link ie.bitstep.mango.crypto.annotations.UniqueGroup#order()}.
	 *
	 * @return ordered set of unique group members
	 */
	public Set<UniqueGroupMember> getUniqueGroupWrappers() {
		return uniqueGroupMembers;
	}
}
