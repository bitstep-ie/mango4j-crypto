package ie.bitstep.mango.crypto.domain;

import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;

import java.util.Collection;

/**
 * Any application entities which use the {@link ListHmacFieldStrategy ListHmacFieldStrategy} and which have one or more
 * {@link Hmac @Hmac} fields with a {@link Hmac.Purposes#LOOKUP LOOKUP} purpose must implement this interface.
 */
public interface Lookup {
	/**
	 * The library will generate {@link CryptoShieldHmacHolder HMACs} for all the lookup fields and call this method on the entity.
	 * It's up to the entity to persist the {@link HmacHolder hmacHolders} correctly. This involves completely replacing the
	 * existing lookups on the entity with the collection passed in here (for SQL DBs all existing entries should be
	 * deleted first before persisting).
	 * For SQL DBs these values will probably be stored in a separate lookup fields table. For document DBs this will
	 * probably just be an indexed list inside the entity document.
	 *
	 * @param hmacHolders Collection of {@link CryptoShieldHmacHolder HmacHolders} with all calculated HMACs
	 */
	void setLookups(Collection<CryptoShieldHmacHolder> hmacHolders);

	/**
	 * This method is used by the library to avoid throwing away old HMACs (which could cause problems) during HMAC
	 * calculation. It's also used by the rekey job to avoid re-calculating HMACs for keys which already have HMACs
	 * calculated in the existing entity (because for rekey we know no source values have been changed so re-calculating
	 * the same HMACs is redundant).
	 *
	 * @return Collection containing all the current {@link CryptoShieldHmacHolder HMACs} for the entity.
	 */
	Collection<CryptoShieldHmacHolder> getLookups();
}
