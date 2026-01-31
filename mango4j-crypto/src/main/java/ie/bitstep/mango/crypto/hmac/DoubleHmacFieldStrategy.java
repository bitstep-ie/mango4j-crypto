package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.exceptions.ActiveHmacKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.CryptoKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.TransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.utils.ReflectionUtils;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ie.bitstep.mango.crypto.hmac.FieldValidator.validateSourceHmacField;
import static ie.bitstep.mango.crypto.utils.ReflectionUtils.getFieldStringValue;
import static java.lang.String.format;

/**
 * This is the simplest strategy that SQL based applications can use to solve the 2 core challenges with HMAC key rotation
 * (while having as little impact to normal application performance as possible) which are outlined extensively in the
 * mango4j-crypto-core official documentation. Please make sure that you have read this documentation before
 * implementing Application Level Encryption in your application.
 * <p>
 * If you are using a document style database or performance is not an issue then you might consider using the
 * {@link ListHmacFieldStrategy} instead.
 * </p>
 */
public class DoubleHmacFieldStrategy implements HmacStrategy {

	/**
	 * All (transient) fields marked with {@link Hmac @Hmac} in an entity using this strategy must have an associated
	 * persisted field whose name is the same as this annotated field name plus this suffix.
	 * <p>
	 * e.g. if an entity has a (transient) field called 'userName' annotated with the {@link Hmac @Hmac} annotation
	 * then it also needs to have a field called 'userNameHmac1' (and another field called 'userNameHmac2' - see below)
	 * where this library will write the generated HMAC value
	 * </p>
	 */
	public static final String HMAC_1_FIELD_NAME_SUFFIX = "Hmac1";

	/**
	 * All (transient) fields marked with {@link Hmac @Hmac} in an entity using this strategy must have an associated
	 * persisted field whose name is the same as this annotated field name plus this suffix.
	 * <p>
	 * e.g. if an entity has a (transient) field called 'userName' annotated with the {@link Hmac @Hmac} annotation
	 * then it also needs to have a field called 'userNameHmac2' (and another field called 'userNameHmac1' - see above)
	 * where this library will write the generated HMAC value
	 * </p>
	 */
	public static final String HMAC_2_FIELD_NAME_SUFFIX = "Hmac2";

	private final Map<Field, List<Field>> entityHmacFields = new HashMap<>();
	private final HmacStrategyHelper hmacStrategyHelper;

	/**
	 * Creates a double-HMAC strategy for the supplied entity class.
	 *
	 * @param annotatedEntityClass the entity class to inspect
	 * @param hmacStrategyHelper   helper used to compute HMACs
	 */
	public DoubleHmacFieldStrategy(Class<?> annotatedEntityClass, HmacStrategyHelper hmacStrategyHelper) {
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
			Field targetHmacField1 = allFields.stream()
					.filter(field -> field.getName().equals(hmacSourceField.getName() + HMAC_1_FIELD_NAME_SUFFIX))
					.findFirst()
					.orElseThrow(() -> new NonTransientCryptoException(format("Field '%1$s' does not have an associated field called '%1$s%2$s'", hmacSourceField.getName(), HMAC_1_FIELD_NAME_SUFFIX)));
			targetHmacField1.setAccessible(true); // NOSONAR
			Field targetHmacField2 = allFields.stream()
					.filter(field1 -> field1.getName().equals(hmacSourceField.getName() + HMAC_2_FIELD_NAME_SUFFIX))
					.findFirst()
					.orElseThrow(() -> new NonTransientCryptoException(format("Field '%1$s' does not have an associated field called '%1$s%2$s'", hmacSourceField.getName(), HMAC_2_FIELD_NAME_SUFFIX)));
			targetHmacField2.setAccessible(true); // NOSONAR
			entityHmacFields.put(hmacSourceField, List.of(targetHmacField1, targetHmacField2));
		});
	}

	/**
	 * Calculates HMAC values for all configured fields and sets the corresponding HMAC targets.
	 *
	 * @param entity the entity to process
	 */
	@Override
	public void hmac(Object entity) {
		for (Map.Entry<Field, List<Field>> entry : entityHmacFields.entrySet()) {
			Field sourceField = entry.getKey();
			List<Field> targetHmacFields = entry.getValue();
			String fieldValue = getFieldStringValue(entity, sourceField);
			if (fieldValue == null) {
				// Don't bother trying to HMAC null values
				continue;
			}
			try {
				List<CryptoKey> currentHmacKeys = hmacStrategyHelper.cryptoKeyProvider().getCurrentHmacKeys();
				List<HmacHolder> hmacHolders = currentHmacKeys.stream()
						.map(cryptoKey -> new HmacHolder(cryptoKey, fieldValue, sourceField.getName()))
						.toList();
				hmacStrategyHelper.encryptionService().hmac(hmacHolders);
				targetHmacFields.get(0).set(entity, hmacHolders.get(0).getValue()); // NOSONAR
				if (hmacHolders.size() == 1) {
					targetHmacFields.get(1).set(entity, hmacHolders.get(0).getValue()); // NOSONAR
				} else {
					targetHmacFields.get(1).set(entity, hmacHolders.get(1).getValue()); // NOSONAR
				}
			} catch (TransientCryptoException | UnsupportedKeyTypeException |
					 CryptoKeyNotFoundException | ActiveHmacKeyNotFoundException e) {
				throw e;
			} catch (Exception e) {
				throw new NonTransientCryptoException(String.format("An error occurred trying to set the HMAC fields:%s", e.getClass()), e);
			}
		}
	}
}
