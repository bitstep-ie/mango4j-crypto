package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
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
			public Optional<HmacStrategy> getHmacStrategy(Object entity) {
				Optional<HmacStrategy> hmacStrategy = cryptoShield.getHmacStrategy(entity);
				if (hmacStrategy.isPresent() &&
						currentHmacKey != null &&
						hmacStrategy.get().getClass().isAssignableFrom(ListHmacFieldStrategy.class)) {
					RekeyListHmacFieldStrategy rekeyListHmacFieldStrategy = new RekeyListHmacFieldStrategy((ListHmacFieldStrategy) hmacStrategy.get(), currentHmacKey);
					hmacStrategy = Optional.of(rekeyListHmacFieldStrategy);
				} else {
					hmacStrategy = Optional.empty();
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