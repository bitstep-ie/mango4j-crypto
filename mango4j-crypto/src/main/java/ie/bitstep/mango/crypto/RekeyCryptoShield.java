package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.hmac.DoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeyDoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeyListHmacFieldStrategy;

import java.util.Optional;

public class RekeyCryptoShield {
	private final CryptoShield cryptoShield;
	private final CryptoShieldDelegate rekeyCryptoShieldDelegate;

	public RekeyCryptoShield(CryptoShield cryptoShield,
							 CryptoKey currentEncryptionKey,
							 CryptoKey currentHmacKey) {
		this.cryptoShield = cryptoShield;
		this.rekeyCryptoShieldDelegate = new CryptoShieldDelegate() {

			@Override
			public CryptoKey getCurrentEncryptionKey() {
				return currentEncryptionKey;
			}

			@Override
			public CryptoKey getCurrentEncryptionKey(String keySelector) {
				if (currentEncryptionKey == null) {
					return null;
				}

				String currentKeySelector = currentEncryptionKey.getKeySelector();
				if (currentKeySelector == null) {
					// normalize null to empty string for comparison since some keys might have null key selectors and some might have empty string key selectors, but they should be treated the same.
					currentKeySelector = "";
				}
				return keySelector.equals(currentKeySelector) ? currentEncryptionKey : null;
			}

			@Override
			public Optional<HmacStrategy> getHmacStrategy(Object entity) {
				Optional<HmacStrategy> hmacStrategy = cryptoShield.getAnnotatedEntityManager().getHmacStrategy(entity.getClass());
				if (currentHmacKey != null && hmacStrategy.isPresent()) {
					if (hmacStrategy.get().getClass().isAssignableFrom(ListHmacFieldStrategy.class)) {
						RekeyListHmacFieldStrategy rekeyListHmacFieldStrategy = new RekeyListHmacFieldStrategy((ListHmacFieldStrategy) hmacStrategy.get(), currentHmacKey);
						hmacStrategy = Optional.of(rekeyListHmacFieldStrategy);
					} else if (hmacStrategy.get().getClass().isAssignableFrom(DoubleHmacFieldStrategy.class)) {
						hmacStrategy = Optional.of(new RekeyDoubleHmacFieldStrategy((DoubleHmacFieldStrategy) hmacStrategy.get(), currentHmacKey));
					}
				} else {
					return Optional.empty();
				}
				return hmacStrategy;
			}
		};
	}

	public void decrypt(Object entity) {
		cryptoShield.decrypt(entity);
	}

	public void encrypt(Object entity) {
		cryptoShield.encrypt(entity, rekeyCryptoShieldDelegate);
	}
}