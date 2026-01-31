package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.exceptions.ActiveHmacKeyNotFoundException;

import java.util.ArrayList;
import java.util.List;

import static java.time.Instant.now;

/**
 * This HMAC strategy eliminates the problem related to the second question in the {@link SingleHmacFieldStrategy}
 * documentation. So it's slightly better than that HMAC strategy but still not recommended (especially if your
 * entity uses HMACs for unique values).
 * <p>
 * The way key rotation works with this strategy is that when you add the new
 * {@link CryptoKey} to a tenant you also set the {@link CryptoKey#keyStartTime} attribute to some time in the future
 * when you know all instances of your application will have updated their tenant caches and are all seeing this new
 * HMAC key in the tenant's list of HMAC keys. This means that application operations will only start using this key
 * after that date.
 */
public final class SingleHmacFieldStrategyForTimeBasedCryptoKey extends SingleHmacFieldStrategy {

	/**
	 * Creates a time-based single HMAC strategy for the supplied entity class.
	 *
	 * @param annotatedEntityClass the entity class to inspect
	 * @param hmacStrategyHelper   helper used to compute HMACs
	 */
	public SingleHmacFieldStrategyForTimeBasedCryptoKey(Class<?> annotatedEntityClass, HmacStrategyHelper hmacStrategyHelper) {
		super(annotatedEntityClass, hmacStrategyHelper);
	}

	/**
	 * Selects the first HMAC key whose start time is in the past.
	 *
	 * @param currentHmacKeys the current HMAC keys
	 * @return the active HMAC key
	 */
	protected CryptoKey getHmacKeyToUse(List<CryptoKey> currentHmacKeys) {
		List<CryptoKey> filteredCurrentHmacKeys = new ArrayList<>(currentHmacKeys);
		CryptoKey mostRecentKey = super.getHmacKeyToUse(filteredCurrentHmacKeys);
		if (mostRecentKey.getKeyStartTime() != null) {
			if (mostRecentKey.getKeyStartTime().isAfter(now())) {
				filteredCurrentHmacKeys.remove(mostRecentKey);
				if (filteredCurrentHmacKeys.isEmpty()) {
					throw new ActiveHmacKeyNotFoundException();
				}
				return getHmacKeyToUse(filteredCurrentHmacKeys);
			} else {
				return mostRecentKey;
			}
		}
		throw new ActiveHmacKeyNotFoundException();
	}
}