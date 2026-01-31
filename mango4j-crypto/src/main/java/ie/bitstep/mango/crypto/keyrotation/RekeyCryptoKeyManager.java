package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

public interface RekeyCryptoKeyManager {

	/**
	 * Used to mark a {@link CryptoKey} for deletion.
	 * It's up to the application whether or not to completely remove the key from the system at this point.
	 * But it's recommended to simply mark it as deleted and make sure that
	 * {@link ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider} no longer returns that key
	 * from any method again. {@link CryptoKey} can then be completely removed from the system later
	 * (and the underlying key that it references can be destroyed) when application team decide.
	 *
	 * <h4>Important: Make sure this call updates the {@link CryptoKey#lastModifiedDate} field for correct "redundant HMAC purge" functionality</h4>
	 *
	 * @param tenantsDeprecatedCryptoKey
	 */
	void markKeyForDeletion(CryptoKey tenantsDeprecatedCryptoKey);
}
