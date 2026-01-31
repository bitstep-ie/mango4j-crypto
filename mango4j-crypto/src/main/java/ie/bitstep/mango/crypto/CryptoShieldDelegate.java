package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;

import java.util.Optional;

public interface CryptoShieldDelegate {
	/**
	 * Returns the current encryption key.
	 *
	 * @return the current encryption key
	 */
	CryptoKey getCurrentEncryptionKey();

	/**
	 * Returns the HMAC strategy for the supplied entity.
	 *
	 * @param entity the entity instance
	 * @return the HMAC strategy, if available
	 */
	Optional<HmacStrategy> getHmacStrategy(Object entity);
}
