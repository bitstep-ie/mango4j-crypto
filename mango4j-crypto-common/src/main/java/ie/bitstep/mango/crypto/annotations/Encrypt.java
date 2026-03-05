package ie.bitstep.mango.crypto.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Used to mark fields in application entities that need to be encrypted. These fields <u>must</u> also be transient or
 * this library will not allow them to be registered.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface Encrypt {
}