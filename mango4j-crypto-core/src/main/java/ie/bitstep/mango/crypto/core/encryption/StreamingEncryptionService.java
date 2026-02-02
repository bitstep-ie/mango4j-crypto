package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

public class StreamingEncryptionService {

	private static final int DEFAULT_FRAME_SIZE_IN_BYTES = 1_048_576;

	public void encrypt(CryptoStream cryptoStream,
						StreamingEncryptionServiceDelegate streamingEncryptionServiceDelegate) {
		encrypt(cryptoStream, streamingEncryptionServiceDelegate, DEFAULT_FRAME_SIZE_IN_BYTES);
	}
	public void encrypt(CryptoStream cryptoStream,
						StreamingEncryptionServiceDelegate streamingEncryptionServiceDelegate, int frameSizeInBytes) {
		byte[] sourceBytes = new byte[frameSizeInBytes];

		int index = 0;
		int readByte;
		boolean isFinished = false;
		while (index < frameSizeInBytes) {
			try {
				readByte = cryptoStream.inputStream().read();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			if (readByte == -1) {
				sourceBytes = Arrays.copyOf(sourceBytes, index + 1);
				isFinished = true;
				break;
			} else {
				sourceBytes[index] = (byte) readByte;
			}
			++index;
		}

		byte[] encryptedBytes = streamingEncryptionServiceDelegate.encrypt(cryptoStream.encryptionKey(), sourceBytes);
		try {
			cryptoStream.outputStream().write(encryptedBytes);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		if (!isFinished) {
			encrypt(cryptoStream, streamingEncryptionServiceDelegate, frameSizeInBytes);
		}

		try {
			cryptoStream.outputStream().close();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(CryptoStream cryptoStream) {
		return "";
	}

	public void hmac(Collection<HmacHolder> hmacHolders) {

	}
}
