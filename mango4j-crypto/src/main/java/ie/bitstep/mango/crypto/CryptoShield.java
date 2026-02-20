package ie.bitstep.mango.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;
import ie.bitstep.mango.crypto.core.exceptions.ActiveEncryptionKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.TransientCryptoException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.factories.ObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.utils.thread.NamedScheduledExecutorBuilder;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;

import static java.lang.String.valueOf;
import static java.lang.System.Logger.Level.ERROR;

/**
 * Applications that use Entities annotated with the mango4j-crypto annotations (
 * {@link Encrypt @Encrypt},
 * {@link Hmac @Hmac} and
 * {@link EncryptedData @EncryptedData}) can use the methods in this class to perform
 * their cryptographic operations instead of calling {@link EncryptionService} directly.
 * Your annotated entities must first be registered by passing them to the
 * {@link AnnotatedEntityManager#AnnotatedEntityManager(Collection, HmacStrategyHelper)} on application startup
 * for this class to work.
 */
public class CryptoShield {
	private final System.Logger logger = System.getLogger(CryptoShield.class.getName());
	protected final ObjectMapper objectMapper;
	protected final AnnotatedEntityManager annotatedEntityManager;
	protected final CiphertextFormatter ciphertextFormatter;
	protected final ScheduledExecutorService scheduler;
	private final CryptoKeyProvider cryptoKeyProvider;
	private final EncryptionService encryptionService;
	private final CryptoShieldDelegate cryptoShieldDelegate;
	private final RetryConfiguration retryConfiguration;

	private static final String A_S_ERROR_OCCURRED_TRYING_TO_GET_THE_VALUE_OF_FIELD_S_ON_TYPE_S = "A %s error occurred trying to get the value of field: %s on type: %s";

	public static class Builder {
		private Collection<Class<?>> annotatedEntities;
		private ObjectMapperFactory objectMapperFactory;
		private CryptoKeyProvider cryptoKeyProvider;
		private List<EncryptionServiceDelegate> encryptionServiceDelegates;
		private RetryConfiguration retryConfiguration;

		public Builder withAnnotatedEntities(Collection<Class<?>> annotatedEntities) {
			this.annotatedEntities = annotatedEntities;
			return this;
		}

		/**
		 * If this builder method isn't used then we default to {@link ConfigurableObjectMapperFactory}
		 *
		 * @param objectMapperFactory Implementation of {@link ObjectMapperFactory} that the application wants the
		 *                            library to use
		 * @return this builder
		 */
		public Builder withObjectMapperFactory(ObjectMapperFactory objectMapperFactory) {
			this.objectMapperFactory = objectMapperFactory;
			return this;
		}

		public Builder withCryptoKeyProvider(CryptoKeyProvider cryptoKeyProvider) {
			this.cryptoKeyProvider = cryptoKeyProvider;
			return this;
		}

		public Builder withEncryptionServiceDelegates(List<EncryptionServiceDelegate> encryptionServiceDelegates) {
			this.encryptionServiceDelegates = encryptionServiceDelegates;
			return this;
		}

		public Builder withRetryConfiguration(RetryConfiguration retryConfiguration) {
			this.retryConfiguration = retryConfiguration;
			return this;
		}

		public CryptoShield build() {
			return new CryptoShield(
					annotatedEntities,
					objectMapperFactory,
					cryptoKeyProvider,
					encryptionServiceDelegates,
					retryConfiguration
			);
		}
	}

	public CryptoShield(Collection<Class<?>> annotatedEntities,
						ObjectMapperFactory objectMapperFactory,
						CryptoKeyProvider cryptoKeyProvider,
						List<EncryptionServiceDelegate> encryptionServiceDelegates,
						RetryConfiguration retryConfiguration) {
		if (objectMapperFactory == null) {
			objectMapperFactory = new ConfigurableObjectMapperFactory();
		}
		this.objectMapper = objectMapperFactory.objectMapper();
		this.ciphertextFormatter = new CiphertextFormatter(cryptoKeyProvider, objectMapperFactory);
		this.cryptoKeyProvider = cryptoKeyProvider;
		this.encryptionService = new EncryptionService(encryptionServiceDelegates, ciphertextFormatter, objectMapperFactory);
		this.annotatedEntityManager = new AnnotatedEntityManager(annotatedEntities, new HmacStrategyHelper(encryptionService, cryptoKeyProvider));
		this.retryConfiguration = retryConfiguration;

		if (this.retryConfiguration != null) {
			this.scheduler =
					NamedScheduledExecutorBuilder.builder()
							.poolSize(retryConfiguration.poolSize())
							.threadNamePrefix("crypto-retry-task")
							.uncaughtExceptionHandler((t, e) ->
									// log or handle uncaught exceptions
									logger.log(ERROR, "Uncaught in {0}: {1}", t.getName(), e)
							)
							.removeOnCancelPolicy(true)
							.build();
		} else {
			this.scheduler = null;
		}

		this.cryptoShieldDelegate = new CryptoShieldDelegate() {

			@Override
			public Optional<HmacStrategy> getHmacStrategy(Object entity) {
				return annotatedEntityManager.getHmacStrategy(entity.getClass());
			}

			@Override
			public CryptoKey getCurrentEncryptionKey() {
				return cryptoKeyProvider.getCurrentEncryptionKey();
			}
		};
	}

	/**
	 * This method will encrypt/HMAC all (annotated) fields in your entity and set the corresponding
	 * {@link EncryptedData EncryptedData} and HMAC fields
	 * with the resulting values. The original (transient) fields marked with
	 * {@link Encrypt Encrypt} and
	 * {@link Hmac} will not be modified.
	 *
	 * @param entity Your annotated (and registered) entity
	 */
	public void encrypt(Object entity) {
		// Do NOT add another line to this public method unless you know what you're doing!!!
		encrypt(entity, cryptoShieldDelegate);
	}

	/**
	 * Method to support common serialization functions (usually save functions) which cause the
	 * {@link Encrypt @Encrypt} and
	 * {@link Hmac @Hmac} source fields to be set to null (because they're transient).
	 * e.g. when calling save on an entity using JPA supporting frameworks like hibernate,
	 * in certain cases the framework might set all transient fields to null and may also return an entity object which is not the same as
	 * the original object. Either way after calling save(), all the transient values will be null. If you're going to call
	 * these types of save() functions using Springboot JPA, hibernate or some equivalent serialization function on an entity after encryption,
	 * but you need to continue working with the original source values after that function is called
	 * then use this method instead of the default {@link CryptoShield#encrypt(Object)} and pass in the save() function that
	 * needs to be called. This library will call your save function and return you the object that gets returned from
	 * that function but with all the transient source fields explicitly reset to their original values. So you can continue to work
	 * with them in your code. This will save you having to immediately call decrypt() on a saved entity after calling save() type
	 * functions which have these effects, and thus avoid an unnecessary and wasteful cryptographic operation. For Example:
	 * <pre>
	 *     MyEntity mySavedEntity = encryptAndSerialize(originalEntity, (originalEntity) -> jpaRepository.save(originalEntity));
	 * </pre>
	 *
	 * @param entity                entity which you need to be encrypted and then used to call the serializationFunction
	 * @param serializationFunction The function you want to call after encryption (probably some save() function)
	 * @return the result of your serializationFunction with all transient source fields explicitly reset to their original values
	 * before your serializationFunction was called.
	 */
	public <T> T encryptAndSerialize(T entity, UnaryOperator<T> serializationFunction) {
		Map<Field, Object> originalValues = new HashMap<>();
		annotatedEntityManager.getAllConfidentialFields(entity.getClass()).forEach(sourceField -> {
			try {
				originalValues.put(sourceField, sourceField.get(entity));
			} catch (Exception e) {
				throw new NonTransientCryptoException(
						String.format(A_S_ERROR_OCCURRED_TRYING_TO_GET_THE_VALUE_OF_FIELD_S_ON_TYPE_S, e.getClass().getSimpleName(), sourceField.getName(), entity.getClass().getSimpleName()),
						e
				);
			}
		});
		encrypt(entity, cryptoShieldDelegate);

		T serializedEntity = serializationFunction.apply(entity);
		resetSourceValues(serializedEntity, originalValues);
		return serializedEntity;
	}

	private <T> void resetSourceValues(T serializedEntity, Map<Field, Object> originalValues) {
		if (serializedEntity == null) {
			throw new NonTransientCryptoException("The supplied serialization function returned a null entity, so cannot reset source fields");
		}

		originalValues.forEach((sourceField, originalValue) -> {
			try {
				sourceField.set(serializedEntity, originalValue); // NOSONAR - java:S3011: This library revolves around reflection to set fields
			} catch (Exception e) {
				throw new NonTransientCryptoException(String.format("A %s error occurred trying to reset the original value of field: %s on type: %s", e.getClass().getSimpleName(), sourceField.getName(), sourceField.getDeclaringClass().getSimpleName()),
						e);
			}
		});
	}

	/**
	 * This overloaded method only exists because the rekey job will use different keys for encryption,
	 * so we allow it to pass in its own {@link CryptoShieldDelegate} here instead of calling the normal public
	 * {@link CryptoShield#encrypt(Object)} method.
	 *
	 * @param entity               Your annotated (and registered) entity
	 * @param cryptoShieldDelegate implementation of {@link CryptoShieldDelegate}
	 */
	void encrypt(Object entity, CryptoShieldDelegate cryptoShieldDelegate) {
		if (entity == null) {
			return;
		}

		// recursive block just in case a collection/array was passed
		if (entity instanceof Collection<?> collection) {
			collection.forEach(e -> encrypt(e, cryptoShieldDelegate));
		} else if (entity.getClass().isArray()) {
			if (!Object.class.isAssignableFrom(entity.getClass().getComponentType())) {
				throw new NonTransientCryptoException(String.format("encrypt() method doesn't support arrays of primitive types (%s)", entity.getClass().componentType()));
			}
			Arrays.stream((Object[]) entity).forEach(e -> encrypt(e, cryptoShieldDelegate));
		}

		if (retryConfiguration == null) {
			doEncrypt(entity, cryptoShieldDelegate);
		} else {
			retryableCommand(() -> doEncrypt(entity, cryptoShieldDelegate));
		}
	}

	private void retryableCommand(Runnable command) {
		long backoffDelayInMilliseconds = 0;

		for (int attempts = 1; attempts <= retryConfiguration.maxAttempts(); attempts++) {
			try {
				ScheduledFuture<?> future = scheduler.schedule(command, backoffDelayInMilliseconds, TimeUnit.MILLISECONDS);
				future.get();
				break;
			} catch (InterruptedException interruptedException) {
				Thread.currentThread().interrupt();
				throw new NonTransientCryptoException("Thread was interrupted during retry backoff sleep", interruptedException);
			} catch (ExecutionException ex) {
				if (ex.getCause() instanceof TransientCryptoException cause) {
					if (attempts == retryConfiguration.maxAttempts()) {
						throw cause;
					}
					backoffDelayInMilliseconds = retryConfiguration.backoffDelay().toMillis() + (long) (backoffDelayInMilliseconds * retryConfiguration.backOffMultiplier());
				} else if (ex.getCause() instanceof NonTransientCryptoException cause) {
					throw cause;
				} else {
					throw new NonTransientCryptoException("An error occurred during retry attempt", ex.getCause());
				}
			}
		}
	}

	private void doEncrypt(Object entity, CryptoShieldDelegate cryptoShieldDelegate) {
		setHmacFields(entity, cryptoShieldDelegate);
		setEncryptedDataField(entity, cryptoShieldDelegate);
		setCascadedFields(entity, cryptoShieldDelegate);
	}

	private void setCascadedFields(Object entity, CryptoShieldDelegate cryptoShieldDelegate) {
		annotatedEntityManager.getFieldsToCascadeEncrypt(entity.getClass())
				.forEach(cascadedField -> {
					try {
						if (isProcessableCollection(entity, cascadedField)) {
							((Collection<?>) cascadedField.get(entity)).forEach(cascadedEntity -> encrypt(cascadedEntity, cryptoShieldDelegate));
						} else {
							encrypt(cascadedField.get(entity), cryptoShieldDelegate);
						}
					} catch (Exception e) {
						throw new NonTransientCryptoException(String.format("An error occurred trying to get the value of field '%s' on entity '%s'", cascadedField.getName(), entity.getClass().getSimpleName()), e);
					}
				});
	}

	public Collection<HmacHolder> generateHmacs(String sourceValue) {
		return generateHmacs(sourceValue, null);
	}

	/**
	 * Method to generate HMACs for a given source value using all current HMAC keys. This method is useful
	 * for applications that need to generate HMACs for values outside the context of an annotated entity,
	 * usually for search operations.
	 * @param sourceValue The source value to HMAC
	 * @param name An optional name/alias for the HMAC (can be null)
	 * @return A collection of {@link HmacHolder} objects containing the resulting HMACs
	 */
	public Collection<HmacHolder> generateHmacs(String sourceValue, String name) {
		List<HmacHolder> hmacHolders = cryptoKeyProvider.getCurrentHmacKeys().stream()
				.map(cryptoKey -> new HmacHolder(cryptoKey, sourceValue, name))
				.toList();
		encryptionService.hmac(hmacHolders);
		return hmacHolders;
	}

	private void setHmacFields(Object entity, CryptoShieldDelegate cryptoShieldDelegate) {
		cryptoShieldDelegate.getHmacStrategy(entity)
				.ifPresent(hmacStrategy -> hmacStrategy.hmac(entity));
	}

	Optional<HmacStrategy> getHmacStrategy(Object entity) {
		return annotatedEntityManager.getHmacStrategy(entity.getClass());
	}

	private void setEncryptedDataField(Object entity, CryptoShieldDelegate cryptoShieldDelegate) {
		List<Field> encryptedFields = annotatedEntityManager.getFieldsToEncrypt(entity.getClass());
		if (encryptedFields.isEmpty()) {
			// maybe this entity only has HMACs
			return;
		}

		if (cryptoShieldDelegate.getCurrentEncryptionKey() == null) {
			// TODO: The delegate check is needed due to the fact that currently the rekey job (currently in BETA) does the
			// re-encrypt and re-HMAC operations separately so cryptoShieldDelegate.getCurrentEncryptionKey() returns null
			// here for the re-HMAC job which isn't a problem and we just return immediately cause there's no encryption to do.
			// This all needs removed when the rekey stuff is refactored.
			if (cryptoShieldDelegate != this.cryptoShieldDelegate) {
				return;
			} else {
				throw new ActiveEncryptionKeyNotFoundException();
			}
		}

		ObjectNode rootNode = convertToJson(entity, encryptedFields);
		try {
			if (!rootNode.isEmpty()) {
				String finalCipherText = ciphertextFormatter.format(doEncrypt(rootNode, cryptoShieldDelegate));
				annotatedEntityManager.getEncryptedDataField(entity.getClass()).set(entity, finalCipherText); // NOSONAR - we set accessible to true on startup
			}
			Optional<Field> encryptionKeyIdFieldMaybe = annotatedEntityManager.getEncryptionKeyIdField(entity.getClass());
			if (encryptionKeyIdFieldMaybe.isPresent()) {
				encryptionKeyIdFieldMaybe.get().set(entity, cryptoShieldDelegate.getCurrentEncryptionKey().getId()); // NOSONAR - we set accessible to true on startup
			}
		} catch (NonTransientCryptoException e) {
			throw e;
		} catch (Exception e) {
			throw new NonTransientCryptoException(String.format("An error occurred trying to create the ciphertext:%s", e.getClass()), e);
		}
	}

	private ObjectNode convertToJson(Object entity, List<Field> encryptedFields) {
		ObjectNode rootNode = objectMapper.createObjectNode();
		encryptedFields.forEach(sourceField -> {
			try {
				Object sourceFieldValue = sourceField.get(entity);
				if (sourceFieldValue != null) {
					JsonNode fieldValue = objectMapper.convertValue(sourceFieldValue, JsonNode.class);
					if (fieldValue != null && fieldValue.getNodeType() != JsonNodeType.NULL
							&& fieldValue.getNodeType() != JsonNodeType.MISSING) {
						rootNode.set(sourceField.getName(), fieldValue);
					}
				}
			} catch (Exception e) {
				throw new NonTransientCryptoException(String.format(A_S_ERROR_OCCURRED_TRYING_TO_GET_THE_VALUE_OF_FIELD_S_ON_TYPE_S, e.getClass().getSimpleName(), sourceField.getName(), entity.getClass().getSimpleName()), e);
			}
		});
		return rootNode;
	}

	private CiphertextContainer doEncrypt(ObjectNode rootNode, CryptoShieldDelegate cryptoShieldDelegate) throws JsonProcessingException {
		return encryptionService.encrypt(cryptoShieldDelegate.getCurrentEncryptionKey(), objectMapper.writeValueAsString(rootNode));
	}

	/**
	 * Decrypts and resets all fields annotated with
	 * {@link Encrypt Encrypt}
	 * {@link Hmac Hmac} in your entity to their original values
	 *
	 * @param entity Your annotated entity which has previously been encrypted.
	 */
	public void decrypt(Object entity) {
		if (entity == null) {
			return;
		}

		if (entity instanceof Collection<?> collection) {
			collection.forEach(this::decrypt);
		} else {
			if (retryConfiguration == null) {
				doDecrypt(entity);
			} else {
				retryableCommand(() -> doDecrypt(entity));
			}
		}

	}

	private void doDecrypt(Object entity) {
		resetFieldsFromEncryptedData(entity);
		resetCascadedFieldsFromEncryptedData(entity);
	}

	private void resetCascadedFieldsFromEncryptedData(Object entity) {
		annotatedEntityManager.getFieldsToCascadeEncrypt(entity.getClass())
				.forEach(cascadedField -> {
					try {
						if (isProcessableCollection(entity, cascadedField)) {
							((Collection<?>) cascadedField.get(entity)).forEach(this::decrypt);
						} else {
							decrypt(cascadedField.get(entity));
						}
					} catch (Exception e) {
						throw new NonTransientCryptoException(String.format(A_S_ERROR_OCCURRED_TRYING_TO_GET_THE_VALUE_OF_FIELD_S_ON_TYPE_S, e.getClass().getSimpleName(), cascadedField.getName(), entity.getClass().getSimpleName()), e);
					}
				});
	}

	private static boolean isProcessableCollection(Object entity, Field cascadedField) throws IllegalAccessException {
		return Collection.class.isAssignableFrom(cascadedField.getType()) &&
				cascadedField.get(entity) != null;
	}

	@SuppressWarnings({"java:S2209"})
	// Sonar bug: incorrectly flags line as java:S2209. Thinks it's a static reference, no idea why.
	private void resetFieldsFromEncryptedData(Object entity) {
		try {
			List<Field> fieldsToEncrypt = annotatedEntityManager.getFieldsToEncrypt(entity.getClass());
			if (fieldsToEncrypt.isEmpty()) {
				// TODO: maybe this entity only has HMACs - revisit: should we throw an exception here to warn
				// app that decrypt was called on an object that can't be decrypted?
				return;
			}

			Object encryptedData = annotatedEntityManager.getEncryptedDataField(entity.getClass()).get(entity);
			if (encryptedData == null) {
				return;
			}

			String finalCiphertext = valueOf(encryptedData);
			JsonNode decryptedJsonNode = objectMapper.readTree(encryptionService.decrypt(finalCiphertext));
			for (Field field : fieldsToEncrypt) {
				JsonNode fieldValue = decryptedJsonNode.get(field.getName());
				if (fieldValue != null) {
					field.set(entity, objectMapper.treeToValue(fieldValue, field.getType())); // NOSONAR
				}
			}
		} catch (TransientCryptoException e) {
			throw e;
		} catch (Exception e) {
			throw new NonTransientCryptoException(String.format("An error occurred trying to decrypt the ciphertext:%s", e.getClass()), e);
		}
	}

	public CryptoKeyProvider getCryptoKeyProvider() {
		return cryptoKeyProvider;
	}
}