package ie.bitstep.mango.crypto.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation used to tell CryptoShield to apply the encryption/decryption operation to this embedded object also.
 * Used when you have a complex model structure containing sub-entities (or collections of sub-entities) which
 * you also want to apply the cryptographic operation to.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface CascadeEncrypt {
}
