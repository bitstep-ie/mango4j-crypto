package ie.bitstep.mango.crypto.annotations;

import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Used by {@link ListHmacFieldStrategy ListHmacFieldStrategy}
 * to mark fields in application entities that need multiple HMACs to be calculated together to support a compound
 * unique constraint . These fields can be both transient @{@link Hmac} fields or regular non-transient non (@{@link Hmac})
 * fields. This is to support the case where one or more of the fields in the compound unique constraint
 * may not be a confidential field. At least one field must be marked @{@link Hmac} (otherwise there would be no point
 * in using this library to do this when you can just place the compound unique constraint on all of your cleartext fields)
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
@Repeatable(UniqueGroups.class)
public @interface UniqueGroup {

	/**
	 * The name of the compound unique constraint group that this field belongs to. Fields with matching values for this
	 * field will be calculated together as part of a single compound unique constraint.
	 * @return - Some name that helps you group together multiple fields that are part of a compound unique constraint.
	 */
	String name();

	/**
	 * The order of this field in the unique constraint group.
	 * <p>
	 *     <font size="14"><b>Important!!!</b></font> - never change this value in your application. If you do then the resulting compound unique
	 *     constraint will be calculated differently and you are exposed to having duplicates in your application.
	 * </p>
	 * @return The location of this field in the unique group order.
	 */
	int order();

	/**
	 * Some compound unique constraints have a requirement whereby if some of the fields has a null/empty/missing value
	 * then the unique constraint should not be enforced. This should be set to true on any fields in a unique group for
	 * which this is true.
	 * @return true if this unique constraint should not be calculated if the source value for this particular field
	 * is null or empty, false otherwise.
	 */
	boolean isOptional() default false;
}

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
@interface UniqueGroups {
	/**
	 * Container annotation for repeatable {@link UniqueGroup}.
	 *
	 * @return the contained annotations
	 */
	UniqueGroup[] value();
}
