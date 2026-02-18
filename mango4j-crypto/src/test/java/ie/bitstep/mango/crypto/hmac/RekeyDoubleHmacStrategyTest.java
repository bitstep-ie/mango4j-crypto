package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.testdata.TestData;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
public class RekeyDoubleHmacStrategyTest {

	@Mock
	private DoubleHmacFieldStrategy mockDoubleHmacStrategy;

	@Mock
	private CryptoKey mockHmacKey;

	private DoubleHmacFieldStrategyDelegate doubleHmacFieldStrategyDelegate;
	private RekeyDoubleHmacFieldStrategy rekeyDoubleHmacFieldStrategy;
	private TestAnnotatedEntityForDoubleHmacFieldStrategy testEntity;
	private CryptoKey testCurrentHmacKey;

	@BeforeEach
	void setup() throws NoSuchFieldException, IllegalAccessException {
		testCurrentHmacKey = TestData.testCryptoKey();
		rekeyDoubleHmacFieldStrategy = new RekeyDoubleHmacFieldStrategy(mockDoubleHmacStrategy, testCurrentHmacKey);
		Field noOpDoubleHmacFieldStrategyDelegate = rekeyDoubleHmacFieldStrategy.getClass().getDeclaredField("noOpDoubleHmacFieldStrategyDelegate");
		noOpDoubleHmacFieldStrategyDelegate.setAccessible(true);
		doubleHmacFieldStrategyDelegate = (DoubleHmacFieldStrategyDelegate) noOpDoubleHmacFieldStrategyDelegate.get(rekeyDoubleHmacFieldStrategy);

		testEntity = new TestAnnotatedEntityForDoubleHmacFieldStrategy();
		testEntity.setPan(TEST_PAN);
	}

	@Test
	void hmac() {
		rekeyDoubleHmacFieldStrategy.hmac(testEntity);

		then(mockDoubleHmacStrategy).should().hmac(testEntity, doubleHmacFieldStrategyDelegate);
	}

	@Test
	void getCurrentHmacKeys() {
		assertThat(doubleHmacFieldStrategyDelegate.getCurrentHmacKeys()).isEqualTo(List.of(testCurrentHmacKey));
		assertThatCode(() -> doubleHmacFieldStrategyDelegate.setFieldForOlderHmacKey(null, null, null))
				.doesNotThrowAnyException();
	}
}
