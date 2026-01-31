package ie.bitstep.mango.crypto.core.domain;

/**
 * Represents the type of cryptographic operations that the associated {@link CryptoKey} will perform.
 */
public enum CryptoKeyUsage {
	ENCRYPTION,
	HMAC
}