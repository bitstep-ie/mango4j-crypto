package ie.bitstep.mango.crypto.core;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.exceptions.CachedKeyInstantiationException;
import ie.bitstep.mango.crypto.core.exceptions.KeyAlreadyDestroyedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@SuppressWarnings("resource")
class CachedWrappedKeyHolderTest {

	public static final UUID TEST_KEY_ID = UUID.randomUUID();

	private static CiphertextContainer createCryptoKeyContainer() {
		return new CiphertextContainer(
				new CryptoKey(),
				new LinkedHashMap<>()
		);
	}

	@SuppressWarnings("unchecked")
	@AfterEach
	void tearDown() throws NoSuchFieldException, IllegalAccessException {
		InMemoryKeyVault.INSTANCE.remove(TEST_KEY_ID);
		Field keyGeneratorField = InMemoryKeyVault.class.getDeclaredField("store");
		keyGeneratorField.setAccessible(true);
		((Map<UUID, InMemoryKeyVault.VaultEntry>) keyGeneratorField.get(InMemoryKeyVault.INSTANCE)).clear();
	}

	@Test
	void constructorNullKeyBytes() {
		assertThatThrownBy(() -> new CachedWrappedKeyHolder(
				"TestKeyId",
				null,
				createCryptoKeyContainer()))
				.isInstanceOf(CachedKeyInstantiationException.class)
				.hasMessage("Key cannot be null or empty!");
	}

	@Test
	void constructorEmptyKeyBytes() {
		assertThatThrownBy(() -> new CachedWrappedKeyHolder(
				"TestKeyId",
				new byte[]{},
				createCryptoKeyContainer()))
				.isInstanceOf(CachedKeyInstantiationException.class)
				.hasMessage("Key cannot be null or empty!");
	}

	@Test
	@Timeout(10)
// see the PIT related comment at the end of the test for why we need this
	void key() {
		byte[] key = new byte[]{1, 2, 2, 2, 2, 2, 5, 2};
		CachedWrappedKeyHolder cachedWrappedKeyHolder = spy(
				new CachedWrappedKeyHolder(
						TEST_KEY_ID.toString(),
						key,
						createCryptoKeyContainer()));

		assertThat(cachedWrappedKeyHolder.key()).isEqualTo(key);

// The following assert is for PIT tests. They remove the call to readlock.unlock() in the key() method.
// We want to make sure that when that happens the test fails by another thread trying to get the writelock and timing out the test
		assertThatNoException().isThrownBy(() -> Executors.newSingleThreadExecutor().submit(cachedWrappedKeyHolder::close).get());
	}

	@Test
	void keyAlreadyClosed() {
		byte[] key = new byte[]{1, 2, 2, 2, 2, 2, 5, 2};
		CachedWrappedKeyHolder cachedWrappedKeyHolder = spy(
				new CachedWrappedKeyHolder(
						TEST_KEY_ID.toString(),
						key,
						createCryptoKeyContainer()));

		cachedWrappedKeyHolder.close();

		assertThatThrownBy(cachedWrappedKeyHolder::key)
				.isInstanceOf(KeyAlreadyDestroyedException.class)
				.hasMessage(null);
	}

	@Test
	@Timeout(10)
// see the PIT related comment at the end of the test for why we need this
	void testClose() {
		String keyId = TEST_KEY_ID.toString();
		int sizeBefore = InMemoryKeyVault.INSTANCE.size();
		byte[] keyBytes = new byte[]{1, 23, 3, 4, 5, 6, 6};
		CachedWrappedKeyHolder cachedWrappedKeyHolder = spy(
				new CachedWrappedKeyHolder(
						keyId,
						keyBytes,
						createCryptoKeyContainer()));

		try (cachedWrappedKeyHolder) {
// NOSONAR: intentionally empty
		}

		assertThat(InMemoryKeyVault.INSTANCE.size()).isEqualTo(sizeBefore);
		verify(cachedWrappedKeyHolder).close();

// The following assert is for PIT tests. They remove the call to writelock.unlock() in the close() method.
// We want to make sure that when that happens the test fails by another thread trying to get the readlock and timing out the test
		assertThatThrownBy(() -> Executors.newSingleThreadExecutor().submit(cachedWrappedKeyHolder::key).get())
				.isInstanceOf(ExecutionException.class)
				.hasCauseInstanceOf(KeyAlreadyDestroyedException.class);
	}

	@Test
	void testCloseKeyAlreadyClosed() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder = spy(
				new CachedWrappedKeyHolder(
						TEST_KEY_ID.toString(),
						new byte[]{1, 23, 3, 4, 5, 6, 6},
						createCryptoKeyContainer()));

		try (cachedWrappedKeyHolder) {
// NOSONAR: intentionally empty
		}

		assertThatNoException().isThrownBy(cachedWrappedKeyHolder::close);
	}

	@Test
	void equalsEquivalentObjects() {
		String keyId = TEST_KEY_ID.toString();

		CachedWrappedKeyHolder cachedWrappedKeyHolder1 = new CachedWrappedKeyHolder(
				keyId,
				new byte[32],
				createCryptoKeyContainer());

		CachedWrappedKeyHolder cachedWrappedKeyHolder2 = new CachedWrappedKeyHolder(
				keyId,
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder1.equals(cachedWrappedKeyHolder2)).isTrue();
	}

	@Test
	void equalsDifferentKeyIds() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder1 = new CachedWrappedKeyHolder(
				UUID.randomUUID().toString(),
				new byte[32],
				createCryptoKeyContainer());

		CachedWrappedKeyHolder cachedWrappedKeyHolder2 = new CachedWrappedKeyHolder(
				TEST_KEY_ID.toString(),
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder1.equals(cachedWrappedKeyHolder2)).isFalse();
	}

	@SuppressWarnings("ConstantValue")
	@Test
	void equalsToNullFail() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder1 = new CachedWrappedKeyHolder(
				TEST_KEY_ID.toString(),
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder1.equals(null)).isFalse();
	}

	@Test
	void equalsKeyIdIsEmptyString() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder1 = new CachedWrappedKeyHolder(
				TEST_KEY_ID.toString(),
				new byte[32],
				createCryptoKeyContainer());

		CachedWrappedKeyHolder cachedWrappedKeyHolder2 = new CachedWrappedKeyHolder(
				"",
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder1.equals(cachedWrappedKeyHolder2)).isFalse();
	}

	@SuppressWarnings("EqualsWithItself")
	@Test
	void equalsToItself() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder = new CachedWrappedKeyHolder(
				TEST_KEY_ID.toString(),
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder.equals(cachedWrappedKeyHolder)).isTrue();
	}

	@Test
	void equalsDifferentTypeOfObject() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder = new CachedWrappedKeyHolder(
				TEST_KEY_ID.toString(),
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder.equals(new Object())).isFalse();
	}

	@Test
	void hashCodeSuccess() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder = new CachedWrappedKeyHolder(
				"0aa09e28-49b0-491a-9211-be0742174f28",
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder.hashCode()).isEqualTo(-72194015);
	}

	@Test
	void toStringSuccess() {
		CachedWrappedKeyHolder cachedWrappedKeyHolder = new CachedWrappedKeyHolder(
				"0aa09e28-49b0-491a-9211-be0742174f28",
				new byte[32],
				createCryptoKeyContainer());

		assertThat(cachedWrappedKeyHolder).hasToString("WrappedKeyHolder(KeyId: 0aa09e28-49b0-491a-9211-be0742174f28)");
	}

	@Test
	void persistableEncryptedKey() {
		CiphertextContainer cryptoKeyContainer = createCryptoKeyContainer();
		CachedWrappedKeyHolder cachedWrappedKeyHolder = new CachedWrappedKeyHolder(
				"TestKeyId",
				new byte[32],
				cryptoKeyContainer);
		assertThat(cachedWrappedKeyHolder.persistableEncryptedKey()).isEqualTo(cryptoKeyContainer);
	}
}