package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.io.InputStream;
import java.io.OutputStream;

public record CryptoStream(InputStream inputStream, OutputStream outputStream, CryptoKey encryptionKey) {
}
