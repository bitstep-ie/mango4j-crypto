package ie.bitstep.mango.crypto.core.aws.impl.service.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GenerateMacResponse;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
public class AwsEncryptionServiceDelegateTest {

	private static final String TEST_CRYPTO_KEY_ID = "TetsCryptoKeyId";
	private static final String TEST_PLAINTEXT_STRING = "Test source data";
	private static final String TEST_AWS_KEY_URN = "testAwsKeyURN";
	private static final String TEST_ALGORITHM_VALUE = "testAlgorithmValue";
	private static final String TEST_CIPHERTEXT = "testCiphertext";
	public static final String AWS_KEY_ID_CONFIG_ATTRIBUTE = "awsKeyId";
	public static final String ALGORITHM_CONFIG_ATTRIBUTE = "algorithm";
	public static final String DATA_CONFIG_ATTRIBUTE = "data";
	public static final String TEST_HMAC_FIELD_NAME = "testHmacFieldName";

	@Mock
	private KmsClient mockAwsKmsClient;

	@Mock
	private EncryptionService mockEncryptionService;

	@Captor
	private ArgumentCaptor<EncryptRequest> encryptRequestCaptor;

	@Captor
	private ArgumentCaptor<DecryptRequest> decryptRequestCaptor;

	@Captor
	private ArgumentCaptor<GenerateMacRequest> generateMacRequestRequestCaptor;

	private CryptoKey testCryptoKey;
	private AwsEncryptionServiceDelegate awsEncryptionServiceDelegate;

	@BeforeEach
	void setup() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		testCryptoKey = new CryptoKey();
		testCryptoKey.setCreatedDate(Instant.now());
		testCryptoKey.setId(TEST_CRYPTO_KEY_ID);
		HashMap<String, Object> awsKeyConfiguration = new HashMap<>();
		awsKeyConfiguration.put(AWS_KEY_ID_CONFIG_ATTRIBUTE, TEST_AWS_KEY_URN);
		awsKeyConfiguration.put(ALGORITHM_CONFIG_ATTRIBUTE, TEST_ALGORITHM_VALUE);
		testCryptoKey.setConfiguration(awsKeyConfiguration);

		awsEncryptionServiceDelegate = new AwsEncryptionServiceDelegate(mockAwsKmsClient);
		Method setEncryptionServiceMethod = AwsEncryptionServiceDelegate.class.getSuperclass().getDeclaredMethod("setEncryptionServiceReference", EncryptionService.class);
		setEncryptionServiceMethod.trySetAccessible();
		setEncryptionServiceMethod.invoke(awsEncryptionServiceDelegate, mockEncryptionService);
	}

	@Test
	void supportedCryptoKeyType() {
		assertThat(awsEncryptionServiceDelegate.supportedCryptoKeyType()).isEqualTo("AWS_KMS");
	}

	@SuppressWarnings("resource")
	@Test
	void encrypt() {
		EncryptResponse testEncryptResponse = EncryptResponse.builder()
				.keyId(TEST_AWS_KEY_URN)
				.encryptionAlgorithm(TEST_ALGORITHM_VALUE)
				.ciphertextBlob(SdkBytes.fromUtf8String(TEST_CIPHERTEXT))
				.build();
		given(mockEncryptionService.getObjectMapperFactory()).willReturn(new ConfigurableObjectMapperFactory());
		given(mockAwsKmsClient.encrypt(encryptRequestCaptor.capture())).willReturn(testEncryptResponse);

		CiphertextContainer ciphertextContainer = awsEncryptionServiceDelegate.encrypt(testCryptoKey, TEST_PLAINTEXT_STRING);

		assertThat(ciphertextContainer.getCryptoKey()).isEqualTo(testCryptoKey);
		assertThat(ciphertextContainer.getData().get(AWS_KEY_ID_CONFIG_ATTRIBUTE)).isEqualTo(TEST_AWS_KEY_URN);
		assertThat(ciphertextContainer.getData().get(ALGORITHM_CONFIG_ATTRIBUTE)).isEqualTo(TEST_ALGORITHM_VALUE);
		assertThat(ciphertextContainer.getData().get(DATA_CONFIG_ATTRIBUTE)).isEqualTo(Base64.getEncoder().encodeToString(TEST_CIPHERTEXT.getBytes(UTF_8)));

		then(mockAwsKmsClient).should().encrypt(encryptRequestCaptor.capture());
		assertThat(encryptRequestCaptor.getValue().keyId()).isEqualTo(TEST_AWS_KEY_URN);
		assertThat(encryptRequestCaptor.getValue().encryptionAlgorithmAsString()).isEqualTo(TEST_ALGORITHM_VALUE);
		assertThat(encryptRequestCaptor.getValue().plaintext()).isEqualTo(SdkBytes.fromByteArray(TEST_PLAINTEXT_STRING.getBytes(UTF_8)));
	}

	@SuppressWarnings("resource")
	@Test
	void decrypt() {
		DecryptResponse testDecryptResponse = DecryptResponse.builder()
				.keyId(TEST_AWS_KEY_URN)
				.encryptionAlgorithm(TEST_ALGORITHM_VALUE)
				.plaintext(SdkBytes.fromUtf8String(TEST_PLAINTEXT_STRING))
				.build();
		given(mockAwsKmsClient.decrypt(decryptRequestCaptor.capture())).willReturn(testDecryptResponse);
		HashMap<String, Object> ciphertextContainerData = new HashMap<>();
		ciphertextContainerData.put(AWS_KEY_ID_CONFIG_ATTRIBUTE, TEST_AWS_KEY_URN);
		ciphertextContainerData.put(ALGORITHM_CONFIG_ATTRIBUTE, TEST_ALGORITHM_VALUE);
		ciphertextContainerData.put(DATA_CONFIG_ATTRIBUTE, Base64.getEncoder().encodeToString(TEST_CIPHERTEXT.getBytes(UTF_8)));

		String plainText = awsEncryptionServiceDelegate.decrypt(new CiphertextContainer(testCryptoKey, ciphertextContainerData));

		assertThat(plainText).isEqualTo(TEST_PLAINTEXT_STRING);

		then(mockAwsKmsClient).should().decrypt(decryptRequestCaptor.capture());
		assertThat(decryptRequestCaptor.getValue().keyId()).isNull();
		assertThat(decryptRequestCaptor.getValue().encryptionAlgorithmAsString()).isNull();
		assertThat(decryptRequestCaptor.getValue().ciphertextBlob()).isEqualTo(SdkBytes.fromByteArray(TEST_CIPHERTEXT.getBytes(UTF_8)));
	}

	@SuppressWarnings("resource")
	@Test
	void hmac() {
		GenerateMacResponse testGenerateMacResponse = GenerateMacResponse.builder()
				.keyId(TEST_AWS_KEY_URN)
				.macAlgorithm(TEST_ALGORITHM_VALUE)
				.mac(SdkBytes.fromUtf8String(TEST_CIPHERTEXT))
				.build();
		given(mockEncryptionService.getObjectMapperFactory()).willReturn(new ConfigurableObjectMapperFactory());
		given(mockAwsKmsClient.generateMac(generateMacRequestRequestCaptor.capture())).willReturn(testGenerateMacResponse);
		HmacHolder hmacHolder = new HmacHolder(testCryptoKey, TEST_PLAINTEXT_STRING, TEST_HMAC_FIELD_NAME);

		awsEncryptionServiceDelegate.hmac(List.of(hmacHolder));

		assertThat(hmacHolder.getCryptoKey()).isEqualTo(testCryptoKey);
		assertThat(hmacHolder.getHmacAlias()).isEqualTo(TEST_HMAC_FIELD_NAME);
		assertThat(hmacHolder.getValue()).isEqualTo(Base64.getEncoder().encodeToString(TEST_CIPHERTEXT.getBytes(UTF_8)));

		then(mockAwsKmsClient).should().generateMac(generateMacRequestRequestCaptor.capture());
		assertThat(generateMacRequestRequestCaptor.getValue().keyId()).isEqualTo(TEST_AWS_KEY_URN);
		assertThat(generateMacRequestRequestCaptor.getValue().macAlgorithmAsString()).isEqualTo(TEST_ALGORITHM_VALUE);
		assertThat(generateMacRequestRequestCaptor.getValue().message()).isEqualTo(SdkBytes.fromByteArray(TEST_PLAINTEXT_STRING.getBytes(UTF_8)));
	}
}