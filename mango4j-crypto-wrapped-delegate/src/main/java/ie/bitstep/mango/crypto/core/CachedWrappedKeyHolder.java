package ie.bitstep.mango.crypto.core;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.exceptions.CachedKeyInstantiationException;
import ie.bitstep.mango.crypto.core.exceptions.KeyAlreadyDestroyedException;

import java.util.UUID;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Due to the fact that this class implements {@link AutoCloseable} things get a bit tricky.
 * Read the javadocs for {@link CachedWrappedKeyHolder#close()} and {@link CachedWrappedKeyHolder#key()} to understand more.
 */
public class CachedWrappedKeyHolder implements AutoCloseable {
	private final String keyId;

	/**
	 * See javadocs for {@link CachedWrappedKeyHolder#close()} and {@link CachedWrappedKeyHolder#key()} to see why
	 * this field is marked as volatile
	 */
	private volatile UUID vaultKeyId;
	private final CiphertextContainer persistableEncryptedKey;
	private final ReadWriteLock lock = new ReentrantReadWriteLock();
	Lock writeLock = lock.writeLock();
	Lock readLock = lock.readLock();

	/**
	 * Creates a cached wrapped key holder.
	 *
	 * @param keyId the key ID
	 * @param key the raw key bytes
	 * @param persistableEncryptedKey the encrypted key container
	 */
	public CachedWrappedKeyHolder(
			String keyId,
			byte[] key,
			CiphertextContainer persistableEncryptedKey) {
		if (key == null || key.length == 0) {
			throw new CachedKeyInstantiationException("Key cannot be null or empty!");
		}
		this.keyId = keyId;
		vaultKeyId = InMemoryKeyVault.INSTANCE.put(key);
		this.persistableEncryptedKey = persistableEncryptedKey;
	}

	/**
	 * This method and the {@link CachedWrappedKeyHolder#key()} method are synchronized to stop callers calling the
	 * {@link CachedWrappedKeyHolder#key()} method while this key destruction is in operation. As soon as this key
	 * destruction process has begun we must guarantee that any references will blow up if they try to get the key
	 */
	@Override
	public void close() {
		try {
			writeLock.lock();
			if (vaultKeyId == null) {
				return;
			}

			UUID tempVaultKeyReference = vaultKeyId;
// disconnect key pointer (vaultId) before destroying the bytes of the key so that if some thread currently
// has a reference to this object then when they call key() they'll get an exception
// rather than some corrupted byte array which might unwittingly be used to perform the encryption.
			vaultKeyId = null;
			InMemoryKeyVault.INSTANCE.remove(tempVaultKeyReference);
		} finally {
			writeLock.unlock();
		}
	}

	/**
	 * Compares holders by key ID.
	 *
	 * @param o the other object
	 * @return true when equal
	 */
	public boolean equals(Object o) {
		if (o == null || this.getClass() != o.getClass()) {
			return false;
		}

		return this == o || this.keyId.equals(((CachedWrappedKeyHolder) o).keyId());
	}

	/**
	 * Returns the hash code for this holder.
	 *
	 * @return the hash code
	 */
	public int hashCode() {
		return keyId.hashCode();
	}

	/**
	 * Returns a string representation of this holder.
	 *
	 * @return the string representation
	 */
	public String toString() {
		return "WrappedKeyHolder(KeyId: " + keyId + ")";
	}

	/**
	 * This method is synchronized to avoid a race condition whereby a class has a reference to this object, but before
	 * it can call this method another thread calls the {@link CachedWrappedKeyHolder#close()} method.
	 * If that happens, the {@link CachedWrappedKeyHolder#close()} method will start destroying the key before or during
	 * the period when the caller uses it and this will cause serious problems.
	 * <p>The worst that can happen now is that they will get a {@link KeyAlreadyDestroyedException} exception
	 * rather than a corrupted key.</p>
	 * <p></p>
	 *
	 * @return A <b><u>copy</u></b> of the key from the vault. Important that this is a copy due to the previously
	 * mentioned race condition.
	 * <p><b>IMPORTANT: Callers should destroy this copy of the key (set all bytes of the returned byte array to zero) after using.</p>
	 * @throws KeyAlreadyDestroyedException In the small chance that this object was destroyed (removed from the cache)
	 *                                      before calling this method then this exception is thrown. Callers can recover by simply throwing away this object
	 *                                      reference and retrying whatever they were trying to do.
	 */
	public byte[] key() throws KeyAlreadyDestroyedException {
		try {
			readLock.lock();
// If the close() method has already been called on this object then throw an exception
			if (vaultKeyId == null) {
				throw new KeyAlreadyDestroyedException();
			}
			return InMemoryKeyVault.INSTANCE.get(vaultKeyId);
		} finally {
			readLock.unlock();
		}
	}

	/**
	 * Returns the key ID.
	 *
	 * @return the key ID
	 */
	public String keyId() {
		return keyId;
	}

	/**
	 * Returns the persistable encrypted key container.
	 *
	 * @return the encrypted key container
	 */
	public CiphertextContainer persistableEncryptedKey() {
		return persistableEncryptedKey;
	}
}
