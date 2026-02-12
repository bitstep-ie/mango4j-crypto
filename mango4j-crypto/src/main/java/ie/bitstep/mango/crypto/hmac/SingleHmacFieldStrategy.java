package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.exceptions.ActiveHmacKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.CryptoKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NoHmacKeysFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.TransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.exceptions.NoHmacFieldsFoundException;
import ie.bitstep.mango.crypto.utils.ReflectionUtils;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ie.bitstep.mango.crypto.hmac.FieldValidator.validateSourceHmacField;
import static ie.bitstep.mango.crypto.utils.ReflectionUtils.getFieldStringValue;
import static java.lang.String.format;
import static java.time.Instant.now;

/**
 * Applications should rarely (almost never) use this strategy.
 * An application should only use this strategy for an entity if the answer to the following 2 questions is <b>'NO!'</b>:
 *     <ol>
 *         <li>
 *             Does any encrypted field in this entity need to be guaranteed unique (has an associated unique constraint)?
 *         </li>
 *         <li>
 *             Would it have a negative impact on the business if the application experienced functional problems
 *             with search operations on this entity during a key rotation?
 *         </li>
 *     </ol>
 * <p>
 *     The reasoning behind these questions are related to the challenges with HMAC key rotation which are outlined
 *     extensively in the mango4j-crypto-core official documentation. Please make sure that you have read this
 *     documentation before implementing Application Level Encryption in your application.
 * </p>
 */
public class SingleHmacFieldStrategy implements HmacStrategy {

	/**
	 * All (transient) fields marked with {@link Hmac @Hmac} in an entity using this strategy must have an associated
	 * persisted field whose name is the same as this annotated field name plus this suffix.
	 * <p>
	 * e.g. if an entity has a (transient) field called 'userName' annotated with the {@link Hmac @Hmac} annotation
	 * then it also needs to have a field called 'userNameHmac' where this library will write the generated HMAC value
	 * </p>
	 */
	public static final String HMAC_FIELD_NAME_SUFFIX = "Hmac";

	private final Map<Field, Field> entityHmacFields = new HashMap<>();
	private final HmacStrategyHelper hmacStrategyHelper;

	/**
	 * Creates a single-HMAC strategy for the supplied entity class.
	 *
	 * @param annotatedEntityClass the entity class to inspect
	 * @param hmacStrategyHelper   helper used to compute HMACs
	 */
	public SingleHmacFieldStrategy(Class<?> annotatedEntityClass, HmacStrategyHelper hmacStrategyHelper) {
		this.hmacStrategyHelper = hmacStrategyHelper;
		this.register(annotatedEntityClass);
	}

	/**
	 * Registers source and target HMAC fields for the entity class.
	 *
	 * @param annotatedEntityClass the entity class to inspect
	 */
	private void register(Class<?> annotatedEntityClass) {
		List<Field> allFields = List.of(annotatedEntityClass.getDeclaredFields());
		List<Field> hmacSourceFields = ReflectionUtils.getFieldsByAnnotation(annotatedEntityClass, Hmac.class);
		hmacSourceFields.forEach(hmacSourceField -> {
			validateSourceHmacField(hmacSourceField, annotatedEntityClass);
			Field targetHmacField = allFields.stream()
					.filter(field -> field.getName().equals(hmacSourceField.getName() + HMAC_FIELD_NAME_SUFFIX))
					.findFirst()
					.orElseThrow(() -> new NonTransientCryptoException(format("Field '%1$s' does not have an associated field called '%1$s%2$s'", hmacSourceField.getName(), HMAC_FIELD_NAME_SUFFIX)));
			targetHmacField.setAccessible(true); // NOSONAR
			entityHmacFields.put(hmacSourceField, targetHmacField);
		});

		if (entityHmacFields.isEmpty()) {
			throw new NoHmacFieldsFoundException(String.format("Class '%s' does not have any fields annotated with %s", annotatedEntityClass.getName(), Hmac.class.getSimpleName()));
		}
	}

	/**
	 * Calculates HMAC values for all configured fields and sets the target HMAC fields.
	 *
	 * @param entity the entity to process
	 */
	@Override
	public void hmac(Object entity) {
		try {
			CryptoKey hmacKeyToUse = getHmacKeyToUse();
			for (Map.Entry<Field, Field> entry : entityHmacFields.entrySet()) {
				Field sourceField = entry.getKey();
				Field targetHmacField = entry.getValue();
				String fieldValue = getFieldStringValue(entity, sourceField);
				if (fieldValue == null) {
					// Don't bother trying to HMAC null values
					continue;
				}
				List<HmacHolder> hmacHolders = List.of(new HmacHolder(hmacKeyToUse, fieldValue, sourceField.getName()));
				hmacStrategyHelper.encryptionService().hmac(hmacHolders);
				targetHmacField.set(entity, hmacHolders.get(0).getValue()); // NOSONAR
			}
		} catch (TransientCryptoException | UnsupportedKeyTypeException |
				 CryptoKeyNotFoundException | ActiveHmacKeyNotFoundException | NoHmacKeysFoundException e) {
			throw e;
		} catch (Exception e) {
			throw new NonTransientCryptoException(format("An error occurred trying to set the HMAC fields:%s", e.getClass()), e);
		}
	}

	/**
	 * Picks the most recent HMAC key from the supplied list whose getKeyStartTime is not set to a value in the future,
	 * if none of the {@link CryptoKey HMAC keys} have a createdDate then this just returns the first one in the list.
	 *
	 * @return the selected HMAC key
	 */
	private CryptoKey getHmacKeyToUse() {
		List<CryptoKey> sortedCryptoKeys = HmacUtils.hmacKeysInCreationDateDescendingOrder(hmacStrategyHelper.cryptoKeyProvider().getCurrentHmacKeys());
		for (CryptoKey cryptoKey : sortedCryptoKeys) {
			if (cryptoKey.getKeyStartTime() != null && cryptoKey.getKeyStartTime().isAfter(now())) {
				continue;
			}
			return cryptoKey;
		}
		throw new ActiveHmacKeyNotFoundException();
	}
}
