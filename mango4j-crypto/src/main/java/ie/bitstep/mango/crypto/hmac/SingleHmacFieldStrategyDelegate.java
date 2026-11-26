package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

@FunctionalInterface
public interface SingleHmacFieldStrategyDelegate {
	/**
	 * Returns the key to use for HMAC calculation.
	 *
	 * @return the selected HMAC key
	 */
	CryptoKey getHmacKeyToUse();
}
