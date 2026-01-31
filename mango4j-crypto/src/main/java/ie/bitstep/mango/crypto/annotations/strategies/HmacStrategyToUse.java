package ie.bitstep.mango.crypto.annotations.strategies;

import ie.bitstep.mango.crypto.hmac.HmacStrategy;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation is used to tell the library which HMAC strategy an entity class uses.
 * <p>
 * For convenience just use {@link ListHmacStrategy @ListHmacStrategy}, {@link DoubleHmacStrategy @DoubleHmacStrategy},
 * {@link SingleHmacStrategy @SingleHmacStrategy} or {@link SingleTimeBasedHmacStrategy @SingleTimeBasedHmacStrategy}
 * instead of this annotation.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
public @interface HmacStrategyToUse {

	/**
	 * Specifies the HMAC strategy class to use.
	 *
	 * @return the strategy class
	 */
	Class<? extends HmacStrategy> value();
}
