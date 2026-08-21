package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

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
