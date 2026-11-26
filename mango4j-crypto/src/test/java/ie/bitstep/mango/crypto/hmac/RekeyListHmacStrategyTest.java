package ie.bitstep.mango.crypto.hmac;

import org.junit.jupiter.api.Test;

import java.util.List;

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RekeyListHmacStrategyTest {

	@Test
	void suppliesTargetKeyAndDelegatesHmac() {
		ListHmacFieldStrategy wrapped = mock(ListHmacFieldStrategy.class);
		RekeyListHmacFieldStrategy rekey = new RekeyListHmacFieldStrategy(wrapped, TEST_CRYPTO_KEY);
		Object entity = new Object();

		assertThat(rekey.getCurrentHmacKeys()).isEqualTo(List.of(TEST_CRYPTO_KEY));
		rekey.hmac(entity);

		verify(wrapped).hmac(entity, rekey);
	}

	@Test
	void nullTargetKeyProducesEmptyKeyList() {
		RekeyListHmacFieldStrategy rekey = new RekeyListHmacFieldStrategy(mock(ListHmacFieldStrategy.class), null);

		assertThat(rekey.getCurrentHmacKeys()).isEmpty();
	}
}
