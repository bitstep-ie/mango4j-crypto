package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;
import ie.bitstep.mango.crypto.domain.Unique;
import ie.bitstep.mango.crypto.tokenizers.HmacTokenizer;
import ie.bitstep.mango.crypto.tokenizers.PanTokenizer;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

public class RekeyListHmacFieldStrategy implements HmacStrategy, ListHmacFieldStrategyDelegate {

	private final ListHmacFieldStrategy wrappedListHmacFieldStrategy;
	private final CryptoKey currentHmacCryptoKeys;

	public RekeyListHmacFieldStrategy(ListHmacFieldStrategy wrappedListHmacFieldStrategy, CryptoKey currentHmacCryptoKeys) {
		this.wrappedListHmacFieldStrategy = wrappedListHmacFieldStrategy;
		this.currentHmacCryptoKeys = currentHmacCryptoKeys;
	}

	public List<CryptoKey> getCurrentHmacKeys() {
		return List.of(currentHmacCryptoKeys);
	}

	/**
	 * We know that for a rekey that the values haven't changed so there's no point in calculating HMACs for HMAC keys
	 * that we've already got HMACs for.
	 *
	 * @param currentHmacKeys HMAC keys currently in use (will not include any {@link CryptoKey HMAC keys} with
	 *                        {@link CryptoKey#rekeyMode} of {@link CryptoKey.RekeyMode#KEY_OFF KEY_OFF})
	 * @param sourceField     Source field which contains the value to calculate the HMAC for
	 * @param fieldValue      original value to calculate the HMAC for
	 * @param entity          Application entity/record being processed
	 * @return List of default (clear-text) {@link HmacHolder HmacHolders} which will contain only entries for {@link CryptoKey HMAC keys}
	 * which do not already appear in the existing lookups/unique collections on the entity
	 */
	public Collection<HmacHolder> getDefaultHmacHolders(List<CryptoKey> currentHmacKeys, Field sourceField, String fieldValue, Object entity) {
		Predicate<CryptoKey> filterPredicate;
		Collection<CryptoShieldHmacHolder> existingLookups = ((Lookup) entity).getLookups();
		if (existingLookups == null || existingLookups.isEmpty()) {
			filterPredicate = currentHmacKey -> true;
		} else {
			filterPredicate = currentHmacKey -> existingLookups.stream().noneMatch(hmacHolder -> hmacHolder.getCryptoKeyId().equals(currentHmacKey.getId()));
		}
		return currentHmacKeys.stream()
			.filter(filterPredicate)
			.map(cryptoKey -> new HmacHolder(cryptoKey, fieldValue, sourceField.getName()))
			.toList();
	}

	/**
	 * For rekey jobs, this method will remove any HMAC holders from the lookup and unique values lists if the existing
	 * entity already contains lookups/unique values for the current keys. There's no point in recalculating them as we know
	 * that the source fields values have not changed.
	 *
	 * <p>
	 * <b>Note 1:</b> Key rotations can also be used to perform an entity lookup/unique value update rather than just moving on/off
	 * keys. e.g. an entity may have an existing field that was not previously a lookup field but now wants to make that field
	 * searchable. This can be carried out by adding the @{@link Lookup} annotation to the field and deploying the new version
	 * of the app. Once the deployment is complete, a {@link CryptoKey.RekeyMode#KEY_ON KEY_ON}
	 * rekey job can be started (the underlying key doesn't have to be new, the app just needs to create a new
	 * {@link CryptoKey} object with a different ID but same values for type, usage and keyMaterial fields - we can call
	 * this a 'self' rekey job).
	 * Once the rekey is complete then all entities will have HMACs for this field making it now searchable.
	 * </p>
	 *
	 * <p>
	 * <b>Note 2:</b> This method does <b><i>not</i></b> remove any tokenized representations from the lookups
	 * regardless of whether or not tokenized HMACs already exist for the current keys. This is to support possible
	 * changes in {@link HmacTokenizer HmacTokenizer} implementations.
	 * e.g. if the {@link PanTokenizer PanTokenizer} had a defect where it calculated
	 * an incorrect tokenized representation, then that defect could be fixed and all entities could then be updated
	 * to include the fix by carrying out a 'self' rekey job (as described in <b>Note 1</b>)
	 * </p>
	 *
	 * @param entity                    Entity which is getting updated
	 * @param newLookupValueHmacHolders list of lookups which are about to have HMACs calculated
	 * @param newUniqueValueHmacHolders list of unique values which are about to have HMACs calculated
	 */
	public void preProcessForRekey(Object entity, List<HmacHolder> newLookupValueHmacHolders,
								   List<HmacHolder> newUniqueValueHmacHolders) {
		if (Lookup.class.isAssignableFrom(entity.getClass()) && ((Lookup) entity).getLookups() != null) {
			Collection<CryptoShieldHmacHolder> existingLookupHmacs = ((Lookup) entity).getLookups();
			for (CryptoShieldHmacHolder existingLookupHmac : existingLookupHmacs) {
				newLookupValueHmacHolders.removeIf(newLookupHmac -> newLookupHmac.getCryptoKey().getId().equals(existingLookupHmac.getCryptoKeyId())
					&& newLookupHmac.getHmacAlias().equals(existingLookupHmac.getHmacAlias())
					// to support possible Tokenizer implementation updates we'll always calculate tokenized values no matter what
					&& newLookupHmac.getTokenizedRepresentation() == null);
			}
		}

		if (Unique.class.isAssignableFrom(entity.getClass()) && ((Unique) entity).getUniqueValues() != null) {
			List<CryptoShieldHmacHolder> existingUniqueValueHmacs = ((Unique) entity).getUniqueValues();
			for (CryptoShieldHmacHolder existingUniqueValueHmac : existingUniqueValueHmacs) {
				newUniqueValueHmacHolders.removeIf(newUniqueValueHmac -> newUniqueValueHmac.getCryptoKey().getId().equals(existingUniqueValueHmac.getCryptoKeyId())
					&& newUniqueValueHmac.getHmacAlias().equals(existingUniqueValueHmac.getHmacAlias())
					// to support possible Tokenizer implementation updates we'll always calculate tokenized values no matter what
					&& newUniqueValueHmac.getTokenizedRepresentation() == null);
			}
		}
	}

	public void hmac(Object entity) {
		wrappedListHmacFieldStrategy.hmac(entity, this);
	}
}
