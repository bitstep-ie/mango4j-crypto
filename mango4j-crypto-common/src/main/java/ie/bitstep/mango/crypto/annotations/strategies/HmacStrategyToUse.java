package ie.bitstep.mango.crypto.annotations.strategies;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation is used to tell the library which HMAC strategy an entity class uses.
 * <p>
 * For convenience just use {@link ListHmacStrategy @ListHmacStrategy}, {@link DoubleHmacStrategy @DoubleHmacStrategy},
 * or {@link SingleHmacStrategy @SingleHmacStrategy}
 * instead of this annotation.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
public @interface HmacStrategyToUse {

	/**
	 * Specifies the HMAC strategy full class name to use.
	 *
	 * @return the strategy full class name
	 */
	String value();
}
