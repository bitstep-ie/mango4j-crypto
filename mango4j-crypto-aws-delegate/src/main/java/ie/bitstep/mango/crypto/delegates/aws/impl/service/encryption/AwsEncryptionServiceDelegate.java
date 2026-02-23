package ie.bitstep.mango.crypto.delegates.aws.impl.service.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GenerateMacResponse;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;

public class AwsEncryptionServiceDelegate extends EncryptionServiceDelegate {

	private static final String AWS_KMS_KEY_TYPE = "AWS_KMS";
	private static final String CIPHER_DATA_NODE = "data";
	private static final String CIPHER_ALGORITHM_NODE = "algorithm";
	private static final String CIPHER_AWS_KEY_ID_NODE = "awsKeyId";
	private static final Charset ENCODING_CHARSET = StandardCharsets.UTF_8;

	private final KmsClient kmsClient;

	public AwsEncryptionServiceDelegate(KmsClient kmsClient) {
		this.kmsClient = kmsClient;
	}

	@Override
	public String supportedCryptoKeyType() {
		return AWS_KMS_KEY_TYPE;
	}

	@Override
	public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
		AwsCryptoKeyConfig awsCryptoKeyConfig = createConfigPojo(encryptionKey, AwsCryptoKeyConfig.class);
		EncryptRequest encryptRequest = EncryptRequest.builder()
				.keyId(awsCryptoKeyConfig.awsKeyId())
				.encryptionAlgorithm(awsCryptoKeyConfig.algorithm())
				.plaintext(SdkBytes.fromByteArray(data.getBytes(ENCODING_CHARSET)))
				.build();

		EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
		HashMap<String, Object> cipherText = new HashMap<>();
		cipherText.put(CIPHER_DATA_NODE, Base64.getEncoder().encodeToString(encryptResponse.ciphertextBlob().asByteArray()));
		cipherText.put(CIPHER_ALGORITHM_NODE, encryptResponse.encryptionAlgorithmAsString());
		cipherText.put(CIPHER_AWS_KEY_ID_NODE, encryptResponse.keyId());
		return new CiphertextContainer(encryptionKey, cipherText);
	}

	@Override
	public String decrypt(CiphertextContainer ciphertextContainer) {
		DecryptRequest decryptRequest = DecryptRequest.builder()
				.ciphertextBlob(SdkBytes.fromByteArray(Base64.getDecoder().decode((String) ciphertextContainer.getData().get(CIPHER_DATA_NODE))))
				.build();

		DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
		return new String(decryptResponse.plaintext().asByteArray(), ENCODING_CHARSET);
	}

	@Override
	public void hmac(Collection<HmacHolder> hmacHolders) {
		hmacHolders.forEach(hmacHolder -> {
			AwsCryptoKeyConfig awsCryptoKeyConfig = createConfigPojo(hmacHolder.getCryptoKey(), AwsCryptoKeyConfig.class);
			GenerateMacRequest generateMacRequest = GenerateMacRequest.builder()
					.keyId(awsCryptoKeyConfig.awsKeyId())
					.macAlgorithm(awsCryptoKeyConfig.algorithm())
					.message(SdkBytes.fromByteArray(hmacHolder.getValue().getBytes(ENCODING_CHARSET)))
					.build();

			GenerateMacResponse generateMacResponse = kmsClient.generateMac(generateMacRequest);
			hmacHolder.setValue(Base64.getEncoder().encodeToString(generateMacResponse.mac().asByteArray()));
		});
	}
}