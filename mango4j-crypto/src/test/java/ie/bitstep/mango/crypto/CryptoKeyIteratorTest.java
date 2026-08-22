package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;

import static ie.bitstep.mango.crypto.testdata.TestData.testCryptoKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoKeyIteratorTest {

	private CryptoKey newerCryptoKey;
	private CryptoKey olderCryptoKey;

	@BeforeEach
	void setup() {
		olderCryptoKey = testCryptoKey();
		olderCryptoKey.setId("older");
		olderCryptoKey.setCreatedDate(Instant.now().minusSeconds(3600));

		newerCryptoKey = testCryptoKey();
		newerCryptoKey.setId("newer");
		newerCryptoKey.setCreatedDate(Instant.now());
	}

	@Test
	void increasingFromOldestIteratesFromOldestToNewest() {
		List<CryptoKey> cryptoKeys = List.of(olderCryptoKey, newerCryptoKey);
		CryptoKeyIterator cryptoKeyIterator = new CryptoKeyIterator(cryptoKeys, CryptoKeyRange.increasingFromOldest());

		assertThat(cryptoKeyIterator.hasNext()).isTrue();
		assertThat(cryptoKeyIterator.next()).isEqualTo(olderCryptoKey);
		assertThat(cryptoKeyIterator.hasNext()).isTrue();
		assertThat(cryptoKeyIterator.next()).isEqualTo(newerCryptoKey);
		assertThat(cryptoKeyIterator.hasNext()).isFalse();
		assertThatThrownBy(cryptoKeyIterator::next).isInstanceOf(NoSuchElementException.class);
	}

	@Test
	void decreasingFromNewestIteratesFromNewestToOldest() {
		List<CryptoKey> cryptoKeys = List.of(olderCryptoKey, newerCryptoKey);
		CryptoKeyIterator cryptoKeyIterator = new CryptoKeyIterator(cryptoKeys, CryptoKeyRange.decreasingFromNewest());

		assertThat(cryptoKeyIterator.hasNext()).isTrue();
		assertThat(cryptoKeyIterator.next()).isEqualTo(newerCryptoKey);
		assertThat(cryptoKeyIterator.hasNext()).isTrue();
		assertThat(cryptoKeyIterator.next()).isEqualTo(olderCryptoKey);
		assertThat(cryptoKeyIterator.hasNext()).isFalse();
		assertThatThrownBy(cryptoKeyIterator::next).isInstanceOf(NoSuchElementException.class);
	}

	@Test
	void emptyListHasNoElements() {
		CryptoKeyIterator cryptoKeyIterator = new CryptoKeyIterator(Collections.emptyList(), CryptoKeyRange.increasingFromOldest());
		assertThat(cryptoKeyIterator.hasNext()).isFalse();
		assertThatThrownBy(cryptoKeyIterator::next).isInstanceOf(NoSuchElementException.class);
	}

	@Test
	void nullRangeCausesNpeOnNext() {
		CryptoKeyIterator cryptoKeyIterator = new CryptoKeyIterator(List.of(newerCryptoKey), null);
		// hasNext relies only on index and size, so it should be true; next will try to dereference range and throw NPE
		assertThat(cryptoKeyIterator.hasNext()).isTrue();
		assertThatThrownBy(cryptoKeyIterator::next).isInstanceOf(NullPointerException.class);
	}
}
