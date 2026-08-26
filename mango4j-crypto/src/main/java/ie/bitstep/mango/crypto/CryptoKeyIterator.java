package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * An iterator for iterating over a list of CryptoKey objects in a specified order
 * (either increasing from oldest or decreasing from newest), defined by the {@link CryptoKeyRange}.
 * <p></p>
 * This class sorts the provided list of CryptoKey objects based on their creation date and allows iteration in the
 * specified order. It is intended for use in scenarios where applications want to search for a HMAC with one key at a
 * time in a particular order, rather than generate HMACs with all possible keys at once due to performance considerations.
 */
public class CryptoKeyIterator implements Iterator<CryptoKey> {
	private final List<CryptoKey> cryptoKeysOldestFirst;
	private final CryptoKeyRange cryptoKeyRange;
	private int index = 0;

	public CryptoKeyIterator(List<CryptoKey> cryptoKeys, CryptoKeyRange cryptoKeyRange) {
		this.cryptoKeysOldestFirst =  new ArrayList<>(cryptoKeys);
		this.cryptoKeysOldestFirst.sort(Comparator.comparing(CryptoKey::getCreatedDate, Comparator.nullsFirst(Comparator.naturalOrder())));
		this.cryptoKeyRange = cryptoKeyRange;
	}

	@Override
	public boolean hasNext() {
		return index < cryptoKeysOldestFirst.size();
	}

	@Override
	public CryptoKey next() {
		if (index >= cryptoKeysOldestFirst.size()) {
			throw new NoSuchElementException("No more crypto keys available in this iterator");
		}
		return CryptoKeyRange.INCREASING_FROM_OLDEST_DIRECTION.equals(cryptoKeyRange.getDirection())
				? cryptoKeysOldestFirst.get(index++)
				: cryptoKeysOldestFirst.get(cryptoKeysOldestFirst.size() - 1 - index++);
	}
}
