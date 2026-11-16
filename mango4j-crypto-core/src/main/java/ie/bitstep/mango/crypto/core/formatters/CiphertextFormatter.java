package ie.bitstep.mango.crypto.core.formatters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.exceptions.CiphertextFormatterException;
import ie.bitstep.mango.crypto.core.factories.ObjectMapperFactory;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

/**
 * Used to convert {@link CiphertextContainer} objects to String and back.
 */
public class CiphertextFormatter {
	private final ObjectMapperFactory objectMapperFactory;

	public static final String DATA_ATTRIBUTE_NAME = "data";
	public static final String CRYPTO_KEY_ID_ATTRIBUTE_NAME = "cryptoKeyId";

	private final CryptoKeyProvider cryptoKeyProvider;

	/**
	 * Basic constructor to create a {@link CiphertextFormatter} instance.
	 * @param cryptoKeyProvider - Your application's implementation of {@link CryptoKeyProvider}
	 */
	public CiphertextFormatter(CryptoKeyProvider cryptoKeyProvider, ObjectMapperFactory objectMapperFactory) {
		this.cryptoKeyProvider = cryptoKeyProvider;
		this.objectMapperFactory = objectMapperFactory;
	}

	/**
	 * Use this method to format your stored ciphertext back into a {@link CiphertextContainer} object for decryption
	 *
	 * @param data ciphertext retrieved from storage
	 * @return {@link CiphertextContainer} object representing the full ciphertext information
	 */
	public CiphertextContainer parse(String data) {
		try {
			JsonNode jsonNode = objectMapperFactory.objectMapper().readTree(data);
			String cryptoKeyId = jsonNode.get(CRYPTO_KEY_ID_ATTRIBUTE_NAME).asText();

			JsonNode dataNode = jsonNode.get(DATA_ATTRIBUTE_NAME);
			return new CiphertextContainer(cryptoKeyProvider.getById(cryptoKeyId), objectMapperFactory.objectMapper().convertValue(dataNode, new TypeReference<>() {
			}));
		} catch (JsonProcessingException e) {
			throw new CiphertextFormatterException(String.format("An error occurred trying to parse the String into a %s", CiphertextContainer.class.getSimpleName()), e);
		}
	}

	/**
	 * Use this method to generate the final ciphertext that your application will store.
	 *
	 * @param ciphertextContainer - {@link CiphertextContainer} containing the encrypted data.
	 *
	 * @return A standard formatted final String to be stored in the application's data store. This will be in the
	 * following format:
	 * <br>
	 * "{"cryptoKeyId" : "SomeCryptoKeyId", "ciphertext":{"key1" : "value1", "key2": "value2"}}
	 */
	public String format(CiphertextContainer ciphertextContainer) {
		try {
			ObjectNode rootNode = objectMapperFactory.objectMapper().createObjectNode();
			rootNode.put(CRYPTO_KEY_ID_ATTRIBUTE_NAME, ciphertextContainer.getCryptoKey().getId());
			JsonNode dataMap = objectMapperFactory.objectMapper().convertValue(ciphertextContainer.getData(), JsonNode.class);
			rootNode.set(DATA_ATTRIBUTE_NAME, dataMap);
			return objectMapperFactory.objectMapper().writeValueAsString(rootNode);
		} catch (Exception e) {
			throw new CiphertextFormatterException(String.format("An error occurred trying to format the %s into a String:%s", CiphertextContainer.class.getSimpleName(), e.getClass().getName()));
		}
	}
}