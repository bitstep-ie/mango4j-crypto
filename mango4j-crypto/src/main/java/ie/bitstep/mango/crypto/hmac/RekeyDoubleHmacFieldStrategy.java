package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.lang.reflect.Field;
import java.util.List;

import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode;

public class RekeyDoubleHmacFieldStrategy implements HmacStrategy {

	private final DoubleHmacFieldStrategy wrappedDoubleHmacFieldStrategy;
	private final DoubleHmacFieldStrategyDelegate noOpDoubleHmacFieldStrategyDelegate;

	public RekeyDoubleHmacFieldStrategy(DoubleHmacFieldStrategy wrappedDoubleHmacFieldStrategy, CryptoKey currentHmacCryptoKey) {
		this.wrappedDoubleHmacFieldStrategy = wrappedDoubleHmacFieldStrategy;
		this.noOpDoubleHmacFieldStrategyDelegate = new DoubleHmacFieldStrategyDelegate() {
			@Override
			public List<CryptoKey> getCurrentHmacKeys() {
				return List.of(currentHmacCryptoKey);
			}

			/**
			 * All rekey jobs for {@link DoubleHmacFieldStrategy} are really just {@link RekeyMode#KEY_ON KEY_ON} jobs
			 * to the latest HMAC key. So when we rekey we just add a HMAC with the new HMAC key into the second HMAC
			 * field and leave the other field alone.
			 * @param entity
			 * @param hmacHolders
			 * @param targetHmacFields
			 */
			@Override
			public void setFieldForOlderHmacKey(Object entity, List<HmacHolder> hmacHolders, List<Field> targetHmacFields) {
				// Do not process the field for the old HMAC key during a rekey
			}
		};
	}

	@Override
	public void hmac(Object entity) {
		wrappedDoubleHmacFieldStrategy.hmac(entity, noOpDoubleHmacFieldStrategyDelegate);
	}
}
