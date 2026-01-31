package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.List;

public interface RekeyService<T> {

	/**
	 * @return The type of the entity that this {@link RekeyService} implementation is for.
	 */
	Class<T> getEntityType();

	/**
	 * Used for {@link ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode#KEY_ON} rekey tasks.
	 *
	 * @param cryptoKey The {@link CryptoKey} we want to find records <b>not</b> using. Implementations should check the type
	 *                  of the key to see what they need to search for. If it's an
	 *                  {@link ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage#ENCRYPTION} key then the application
	 *                  should return any records that were encrypted with some other key(s). If it's a
	 *                  {@link ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage#HMAC} key then the application should
	 *                  return any records that have HMACs that were generated with other key(s) except this one.
	 * @return a list of records that are not using this key. Do not return all records in your table, just return a
	 * batch of them to avoid overloading the database. This method is called over and over by the rekey job until an empty list is returned.
	 */
	List<T> findRecordsNotUsingCryptoKey(CryptoKey cryptoKey);

	/**
	 * Used for {@link ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode#KEY_OFF} rekey tasks.
	 *
	 * @param cryptoKey The {@link CryptoKey} we want to find records currently using. Implementations should check the type
	 *                  of the key to see what they need to search for. If it's an
	 *                  {@link ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage#ENCRYPTION} key then the application
	 *                  should return any records that were encrypted with this key. If it's a
	 *                  {@link ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage#HMAC} key then the application should
	 *                  return any records that have HMACs that were generated with this key but <b><i>not</i></b> the current HMAC key.
	 * @return a list of records that are not using this key. Do not return all records in your table, just return a
	 * batch of them to avoid overloading the database. This method is called over and over by the rekey job until an empty list is returned.
	 */
	List<T> findRecordsUsingCryptoKey(CryptoKey cryptoKey);

	/**
	 * Used to save entities that have been rekeyed by the library.
	 *
	 * @param records List of records to update in the database.
	 */
	void save(List<?> records);

	/**
	 * This method is called by the library to notify the application when certain events happen.
	 * e.g.
	 * <p>When the {@link RekeyEvent.Type} is {@link RekeyEvent.Type#REKEY_FINISHED REKEY_FINISHED} then that means that the rekey job
	 * is has completed for the entity type T and the Cryptokey (that triggered the rekey) {@link RekeyEvent#cryptoKey}</p>
	 *
	 * <p>When the {@link RekeyEvent.Type} is {@link RekeyEvent.Type#PURGE_REDUNDANT_HMACS_ASSOCIATED_WITH_KEY PURGE_REDUNDANT_HMACS_ASSOCIATED_WITH_KEY} then
	 * that means that the HMAC key (described by {@link RekeyEvent#cryptoKey}) has been marked as deleted for long
	 * enough (after completion of the HMAC rekey job for this entity) that no application instances are using that key
	 * anymore. And so any old HMACs left from that key can be removed from the system.
	 *
	 * @param rekeyEvent {@link RekeyEvent} which the application is being notified of.
	 */
	void notify(RekeyEvent rekeyEvent);
}