package ie.bitstep.mango.crypto.hmac;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

class UniqueGroupSet {
	private final Set<Field> fields = new HashSet<>();
	private Map<String, UniqueGroup> groups = new HashMap<>();

	/**
	 * Creates a deep copy of an existing unique group set.
	 *
	 * @param entityUniqueGroups the source unique group set
	 */
	UniqueGroupSet(UniqueGroupSet entityUniqueGroups) {
		this.groups = new HashMap<>(entityUniqueGroups.getGroups());
		this.fields.addAll(groups.values().stream().flatMap(uniqueGroup -> uniqueGroup.getAllFields().stream()).collect(Collectors.toSet()));
	}

	/**
	 * Creates an empty unique group set.
	 */
	UniqueGroupSet() {
	}

	/**
	 * Checks whether the field belongs to any unique group.
	 *
	 * @param field the field to check
	 * @return true if the field is part of a group
	 */
	boolean contains(Field field) {
		return fields.contains(field);
	}

	/**
	 * Adds a field to its declared unique groups.
	 *
	 * @param field the field to add
	 */
	void add(Field field) {
		ie.bitstep.mango.crypto.annotations.UniqueGroup[] uniqueUniqueGroups = getUniqueGroup(field);
		for (ie.bitstep.mango.crypto.annotations.UniqueGroup uniqueGroup : uniqueUniqueGroups) {
			groups.computeIfAbsent(uniqueGroup.name(), key -> new UniqueGroup()).add(field);
		}
		fields.add(field);
	}

	/**
	 * Adds a set of fields to their declared unique groups.
	 *
	 * @param uniqueGroupFields the fields to add
	 */
	void addAll(Set<Field> uniqueGroupFields) {
		uniqueGroupFields.forEach(this::add);
	}

	/**
	 * Returns the {@link ie.bitstep.mango.crypto.annotations.UniqueGroup} annotations on the field.
	 *
	 * @param field the field to inspect
	 * @return the unique group annotations
	 */
	private static ie.bitstep.mango.crypto.annotations.UniqueGroup[] getUniqueGroup(Field field) {
		return field.getAnnotationsByType(ie.bitstep.mango.crypto.annotations.UniqueGroup.class);
	}

	/**
	 * Returns the groups keyed by name.
	 *
	 * @return map of group name to group
	 */
	Map<String, UniqueGroup> getGroups() {
		return groups;
	}

	/**
	 * Returns whether the set is empty.
	 *
	 * @return true when no groups are defined
	 */
	boolean isEmpty() {
		return groups.isEmpty();
	}
}
