package ie.bitstep.mango.crypto.annotations.strategies;


import ie.bitstep.mango.crypto.hmac.SingleHmacFieldStrategyForTimeBasedCryptoKey;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Place this annotation on your entity classes if they have HMAC fields, and you want to use the
 * {@link SingleHmacFieldStrategyForTimeBasedCryptoKey Single HMAC Strategy for time-based crypto key}.
 * <p>
 * This annotation must be placed at the class level.
 * </p>
 */
@HmacStrategyToUse(SingleHmacFieldStrategyForTimeBasedCryptoKey.class)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Inherited
public @interface SingleTimeBasedHmacStrategy {
}
