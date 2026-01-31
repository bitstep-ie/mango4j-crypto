package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.annotations.UniqueGroup;

import java.lang.reflect.Field;

/**
 * Represents a field's membership within a unique group and its ordering.
 *
 * @param uniqueGroup the unique group annotation
 * @param field       the field participating in the group
 */
record UniqueGroupMember(UniqueGroup uniqueGroup, Field field) implements Comparable<UniqueGroupMember> {

	/**
	 * Compares members by their unique group order.
	 *
	 * @param o the other member
	 * @return comparison result by order
	 */
	@Override
	public int compareTo(UniqueGroupMember o) {
		return Integer.compare(this.uniqueGroup.order(), o.uniqueGroup.order());
	}
}
