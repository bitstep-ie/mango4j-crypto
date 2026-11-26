package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.List;

public interface ListHmacFieldStrategyDelegate {
	/**
	 * Returns the list of HMAC keys to use for the rekey operation. Currently, it should only be the latest HMAC key, but
	 * we'll keep it a list for now as we've gone back and forth between different internal strategies using multiple active keys
	 *
	 * @return current HMAC keys to rekey to
	 */
	List<CryptoKey> getCurrentHmacKeys();
}
