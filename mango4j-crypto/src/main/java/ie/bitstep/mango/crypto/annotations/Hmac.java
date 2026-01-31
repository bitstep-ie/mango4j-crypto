package ie.bitstep.mango.crypto.annotations;

import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import ie.bitstep.mango.crypto.tokenizers.HmacTokenizer;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static ie.bitstep.mango.crypto.annotations.Hmac.Purposes.LOOKUP;

/**
 * Used to mark fields in application entities that need HMACs to be calculated. These fields <u>must</u> also be transient or
 * this library will not allow them to be registered.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface Hmac {

	/**
	 * Optional: The purposes that fields marked with this annotation will be used for.
	 * This field is only used for entities which use the
	 * {@link ListHmacFieldStrategy ListHmacFieldStrategy}.
	 * <p>
	 * Supported purposes are:
	 * {@link Purposes#LOOKUP LOOKUP} and {@link Purposes#UNIQUE UNIQUE}. Default value is {@link Purposes#LOOKUP LOOKUP}
	 * </p>
	 *
	 * @return Array of HMAC Purposes
	 */
	Purposes[] purposes() default {LOOKUP};

	/**
	 * Used for the {@link ListHmacFieldStrategy} to mark a HMAC field as an optional unique constraint.
	 * <p>
	 *     i.e. if the
	 *     requirement is that a unique constraint should <b><i>not</i></b> be applied if this value is null/empty/missing
	 *     then this should be set to true. If set to false (default) then the unique constraint will always be calculated
	 * </p>
	 * @return true if this unique constraint should not be calculated if the source value is null or empty, false otherwise.
	 */
	boolean isOptionalUnique() default false;

	/**
	 * Optional: The {@link HmacTokenizer HMAC Tokenizers} that should be applied to this field by the library during
	 * HMAC calculation to generate extra HMACs for this field in order to support more flexible search capabilities.
	 * <p>
	 * This field is currently only supported for entities which use the
	 * {@link ListHmacFieldStrategy ListHmacFieldStrategy}.
	 * </p>
	 *
	 * @return Array of {@link HmacTokenizer} implementation classes that the library will apply to this field.
	 */
	Class<? extends HmacTokenizer>[] hmacTokenizers() default {};

	/**
	 * enum representing the different purposes that the HMAC of a field is being used for.
	 */
	enum Purposes {
		/**
		 * Used to mark a HMAC field as being intended for lookup purposes
		 */
		LOOKUP,

		/**
		 * Used to mark a HMAC field as being intended for uniqueness enforcement purposes
		 */
		UNIQUE
	}
}