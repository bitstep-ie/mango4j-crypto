package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.List;

public interface ListHmacFieldStrategyDelegate {
	/**
	 * Returns the list of HMAC keys to use for the operation.
	 *
	 * @return current HMAC keys
	 */
	List<CryptoKey> getCurrentHmacKeys();

	/**
	 * Builds default HMAC holders for the supplied field and value.
	 *
	 * @param currentHmacKeys the current HMAC keys
	 * @param sourceField     the source field being HMACed
	 * @param fieldValue      the field value to HMAC
	 * @param entity          the owning entity
	 * @return default HMAC holders for the field
	 */
	Collection<HmacHolder> getDefaultHmacHolders(List<CryptoKey> currentHmacKeys, Field sourceField, String fieldValue, Object entity);

	/**
	 * This method exists solely for performance benefits during a rekey task. If this is a rekey job, there's no point
	 * in calculating HMACs for {@link CryptoKey CryptoKeys} if HMACs with those same {@link CryptoKey CryptoKeys}
	 * already exist in the entity. This is because we know that the entity hasn't been updated if it's a rekey job.
	 * For normal operations, the source value could have been updated so even if HMACs with particular
	 * {@link CryptoKey CryptoKeys} already exist in the entity then we must recalculate them. Hence, for normal operations
	 * this method does nothing.
	 *
	 * @param entity      the entity being rekeyed
	 * @param lookupHmacs the lookup HMACs generated so far
	 * @param uniqueHmacs the unique HMACs generated so far
	 */

	void preProcessForRekey(Object entity, List<HmacHolder> lookupHmacs, List<HmacHolder> uniqueHmacs);
}
