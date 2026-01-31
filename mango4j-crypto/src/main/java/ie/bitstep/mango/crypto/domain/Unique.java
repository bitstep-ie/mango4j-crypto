package ie.bitstep.mango.crypto.domain;

import java.util.Collection;
import java.util.List;

/**
 * See javadocs for partner interface {@link Lookup}
 */
public interface Unique {
	/**
	 * Replaces the unique values collection for the entity.
	 *
	 * @param hmacHolders the unique HMAC holders
	 */
	void setUniqueValues(Collection<CryptoShieldHmacHolder> hmacHolders);

	/**
	 * Returns the current unique values for the entity.
	 *
	 * @return the unique HMAC holders
	 */
	List<CryptoShieldHmacHolder> getUniqueValues();
}
