package ie.bitstep.mango.crypto.core.testdata;

import java.util.stream.IntStream;

public class TestKeyUtils {

	public static boolean isEmpty(final byte[] data) {
		return IntStream.range(0, data.length).parallel().allMatch(i -> data[i] == 0);
	}
}
