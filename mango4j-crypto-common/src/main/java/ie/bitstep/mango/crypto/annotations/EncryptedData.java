package ie.bitstep.mango.crypto.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Used to mark the field in application entities where this library will place the ciphertext generated from the
 * {@code CryptoShield.encrypt()} operation.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface EncryptedData {
}