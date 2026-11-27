package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.hmac.DoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeyDoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeyListHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeySingleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.SingleHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.TestAnnotatedEntityForSingleHmacFieldStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.Optional;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class RekeyCryptoShieldTest {

	public static final String TEST_SELECTOR_VALUE = "test-selector";
	@Mock
	private CryptoShield mockCryptoShield;

	@Mock
	private AnnotatedEntityManager mockAnnotatedEntityManager;

	@Mock
	private CryptoKey mockEncryptionKey;

	@Mock
	private HmacStrategy mockHmacStrategy;

	@Mock
	private ListHmacFieldStrategy mockListHmacFieldStrategy;

	@Mock
	private DoubleHmacFieldStrategy mockDoubleHmacFieldStrategy;

	@Mock
	private SingleHmacFieldStrategy mockSingleHmacFieldStrategy;

	private RekeyCryptoShield rekeyCryptoShield;

	private TestMockHmacEntity testEntity;

	@BeforeEach
	void setup() {
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, mockEncryptionKey, mockEncryptionKey);
		testEntity = new TestMockHmacEntity();
	}

	@Test
	void constructorNonListHmacStrategy() {
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(mockHmacStrategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity)).isEqualTo(Optional.of(mockHmacStrategy));
	}

	@SuppressWarnings("OptionalGetWithoutIsPresent")
	@Test
	void constructorListHmacStrategy() {
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(mockListHmacFieldStrategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity).get()).isInstanceOf(RekeyListHmacFieldStrategy.class);
	}

	@Test
	void constructorListHmacStrategyButNoHMACKey() {
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, mockEncryptionKey, null);
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(mockListHmacFieldStrategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity)).isNotPresent();
	}

	@SuppressWarnings("OptionalGetWithoutIsPresent")
	@Test
	void constructorDoubleHmacStrategy() {
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(mockDoubleHmacFieldStrategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity).get()).isInstanceOf(RekeyDoubleHmacFieldStrategy.class);
	}

	@Test
	void constructorListHmacSubclass() {
		ListHmacFieldStrategy strategy = mock(CustomListHmacFieldStrategy.class);
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(strategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);

		assertThat(getRekeyCryptoShieldDelegate().getHmacStrategy(testEntity))
				.hasValueSatisfying(wrapped -> assertThat(wrapped).isInstanceOf(RekeyListHmacFieldStrategy.class));
	}

	@Test
	void constructorDoubleHmacSubclass() {
		DoubleHmacFieldStrategy strategy = mock(CustomDoubleHmacFieldStrategy.class);
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(strategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);

		assertThat(getRekeyCryptoShieldDelegate().getHmacStrategy(testEntity))
				.hasValueSatisfying(wrapped -> assertThat(wrapped).isInstanceOf(RekeyDoubleHmacFieldStrategy.class));
	}

	@Test
	void constructorSingleHmacStrategy() {
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(mockSingleHmacFieldStrategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);

		assertThat(getRekeyCryptoShieldDelegate().getHmacStrategy(testEntity))
				.hasValueSatisfying(strategy -> assertThat(strategy).isInstanceOf(RekeySingleHmacFieldStrategy.class));
	}

	@Test
	void constructorSingleHmacSubclass() {
		SingleHmacFieldStrategy strategy = mock(CustomSingleHmacFieldStrategy.class);
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(strategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);

		assertThat(getRekeyCryptoShieldDelegate().getHmacStrategy(testEntity))
				.hasValueSatisfying(wrapped -> assertThat(wrapped).isInstanceOf(RekeySingleHmacFieldStrategy.class));
	}

	@Test
	void singleHmacRekeyUsesExplicitTargetKey() {
		CryptoKey target = new CryptoKey();
		target.setId("target");
		CryptoKeyProvider provider = mock(CryptoKeyProvider.class);
		EncryptionService encryptionService = mock(EncryptionService.class);
		SingleHmacFieldStrategy strategy = new SingleHmacFieldStrategy(
				TestAnnotatedEntityForSingleHmacFieldStrategy.class, new HmacStrategyHelper(encryptionService, provider));
		TestAnnotatedEntityForSingleHmacFieldStrategy entity = new TestAnnotatedEntityForSingleHmacFieldStrategy();
		entity.setPan("pan");
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, null, target);
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		given(mockAnnotatedEntityManager.getHmacStrategy(entity.getClass())).willReturn(Optional.of(strategy));
		doAnswer(invocation -> {
			Collection<HmacHolder> holders = invocation.getArgument(0);
			holders.forEach(holder -> holder.setValue(holder.getCryptoKey().getId() + ":" + holder.getValue()));
			return null;
		}).when(encryptionService).hmac(any());

		getRekeyCryptoShieldDelegate().getHmacStrategy(entity).orElseThrow().hmac(entity);

		assertThat(entity.getPanHmac()).isEqualTo("target:pan");
		assertThat(entity.getHmacKeyId()).isEqualTo("target");
		verifyNoInteractions(provider);
	}

	@Test
	void constructorEmptyHmacStrategy() {
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.empty());
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity)).isNotPresent();
	}

	@Test
	void constructorNoHmacKeys() {
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, mockEncryptionKey, null);
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.empty());
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey("highConfidentialityKeySelector")).isNull();
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity)).isNotPresent();
	}

	@Test
	void getCurrentEncryptionKeyNull() {
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, null, null);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey(TEST_SELECTOR_VALUE)).isNull();
	}

	@Test
	void getCurrentEncryptionKeyWithEmptySelectorReturnsCurrentKey() {
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey("")).isEqualTo(mockEncryptionKey);
	}

	@Test
	void getCurrentEncryptionKeyWithMatchingSelectorReturnsCurrentKey() {
		given(mockEncryptionKey.getKeySelector()).willReturn(TEST_SELECTOR_VALUE);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey(TEST_SELECTOR_VALUE)).isEqualTo(mockEncryptionKey);
	}

	@Test
	void getCurrentEncryptionKeyWithNonMatchingSelectorReturnsNull() {
		given(mockEncryptionKey.getKeySelector()).willReturn(TEST_SELECTOR_VALUE);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey("other-selector")).isNull();
	}

	@Test
	void encrypt() {
		rekeyCryptoShield.encrypt(testEntity);

		then(mockCryptoShield).should().encrypt(testEntity, getRekeyCryptoShieldDelegate());
	}

	@Test
	void decrypt() {
		rekeyCryptoShield.decrypt(testEntity);

		then(mockCryptoShield).should().decrypt(testEntity);
	}

	private CryptoShieldDelegate getRekeyCryptoShieldDelegate() {
		try {
			Field rekeyCryptoShieldDelegate = rekeyCryptoShield.getClass().getDeclaredField("rekeyCryptoShieldDelegate");
			rekeyCryptoShieldDelegate.setAccessible(true);
			return (CryptoShieldDelegate) rekeyCryptoShieldDelegate.get(rekeyCryptoShield);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static class CustomSingleHmacFieldStrategy extends SingleHmacFieldStrategy {
		CustomSingleHmacFieldStrategy(Class<?> entityClass, HmacStrategyHelper helper) {
			super(entityClass, helper);
		}
	}

	private static class CustomListHmacFieldStrategy extends ListHmacFieldStrategy {
		CustomListHmacFieldStrategy(Class<?> entityClass, HmacStrategyHelper helper) {
			super(entityClass, helper);
		}
	}

	private static class CustomDoubleHmacFieldStrategy extends DoubleHmacFieldStrategy {
		CustomDoubleHmacFieldStrategy(Class<?> entityClass, HmacStrategyHelper helper) {
			super(entityClass, helper);
		}
	}
}
