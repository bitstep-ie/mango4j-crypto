package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeyListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
class RekeyCryptoShieldTest {

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

	private RekeyCryptoShield rekeyCryptoShield;

	private TestMockHmacEntity testEntity;

	@BeforeEach
	void setup() {
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, mockEncryptionKey, List.of(mockEncryptionKey));
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
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, mockEncryptionKey, List.of());
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.of(mockListHmacFieldStrategy));
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity)).isNotPresent();
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
		rekeyCryptoShield = new RekeyCryptoShield(mockCryptoShield, mockEncryptionKey, List.of());
		given(mockAnnotatedEntityManager.getHmacStrategy(testEntity.getClass())).willReturn(Optional.empty());
		given(mockCryptoShield.getAnnotatedEntityManager()).willReturn(mockAnnotatedEntityManager);
		CryptoShieldDelegate cryptoShieldDelegate = getRekeyCryptoShieldDelegate();

		assertThat(cryptoShieldDelegate.getCurrentEncryptionKey()).isEqualTo(mockEncryptionKey);
		assertThat(cryptoShieldDelegate.getHmacStrategy(testEntity)).isNotPresent();
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
}
