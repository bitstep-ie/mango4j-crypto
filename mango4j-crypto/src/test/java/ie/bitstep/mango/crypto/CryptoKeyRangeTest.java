package ie.bitstep.mango.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoKeyRangeTest {

	@Test
	void increasingFromOldest() {
		CryptoKeyRange cryptoKeyRangeIncreasingFromOldest1 = CryptoKeyRange.increasingFromOldest();

		assertThat(cryptoKeyRangeIncreasingFromOldest1.getDirection()).isEqualTo("increasing from oldest");
		assertThat(cryptoKeyRangeIncreasingFromOldest1).isSameAs(CryptoKeyRange.increasingFromOldest());
		assertThat(cryptoKeyRangeIncreasingFromOldest1).isNotSameAs(CryptoKeyRange.decreasingFromNewest());
	}

	@Test
	void decreasingFromNewest() {
		CryptoKeyRange cryptoKeyRangeDecreasingFromNewest1 = CryptoKeyRange.decreasingFromNewest();

		assertThat(cryptoKeyRangeDecreasingFromNewest1.getDirection()).isEqualTo("decreasing from newest");
		assertThat(cryptoKeyRangeDecreasingFromNewest1).isSameAs(CryptoKeyRange.decreasingFromNewest());
		assertThat(cryptoKeyRangeDecreasingFromNewest1).isNotSameAs(CryptoKeyRange.increasingFromOldest());
	}
}
