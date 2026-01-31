package ie.bitstep.mango.crypto.functions;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;

/**
 * Collection of methods which can be used to make repository (OR based) HMAC based search operation code less tedious.
 * These methods will execute the underlying repository method with the first element in the provided
 * {@link HmacHolder hmacHolders}, which under normal operations is all that's needed since the list will usually
 * only have a single element for each field (because there's usually only a single HMAC key in use).
 * However, if there are 2 {@link HmacHolder hmacHolder}
 * elements that means that there's 2 HMAC keys currently in use (during key rotation) and we need to also execute the
 * same repository search method again for that element value too.
 */
public final class RotationSupportedRepositoryFunctions {

	/**
	 * Prevents instantiation.
	 */
	private RotationSupportedRepositoryFunctions() {
		throw new AssertionError();
	}

	/**
	 * Executes a repository search that returns an optional using up to two HMAC values.
	 *
	 * @param repositorySearchFunction the repository search function
	 * @param hmacHolders the HMAC holders
	 * @param <T> result type
	 * @return the optional result
	 */
	public static <T> Optional<T> executeOptionalReturningBiFunction(BiFunction<String, String, Optional<T>> repositorySearchFunction,
																	 List<HmacHolder> hmacHolders) {
		Optional<T> result = repositorySearchFunction.apply(hmacHolders.get(0).getValue(), hmacHolders.get(0).getValue());
		if (result.isEmpty() && hmacHolders.size() == 2) {
			result = repositorySearchFunction.apply(hmacHolders.get(1).getValue(), hmacHolders.get(1).getValue());
		}
		return result;
	}

	/**
	 * Executes a repository search that returns a list using up to two HMAC values.
	 *
	 * @param repositorySearchFunction the repository search function
	 * @param hmacHolders the HMAC holders
	 * @param <T> result type
	 * @return the results list
	 */
	public static <T> List<T> executeListReturningBiFunction(BiFunction<String, String, List<T>> repositorySearchFunction,
															 List<HmacHolder> hmacHolders) {
		List<T> results = repositorySearchFunction.apply(hmacHolders.get(0).getValue(), hmacHolders.get(0).getValue());
		if (hmacHolders.size() == 2) {
			results.addAll(repositorySearchFunction.apply(hmacHolders.get(1).getValue(), hmacHolders.get(1).getValue()));
		}
		return results;
	}

	/**
	 * Executes a repository search that returns an optional using two fields with up to two HMAC values each.
	 *
	 * @param repositorySearchFunction the repository search function
	 * @param field1HmacHolders HMAC holders for field 1
	 * @param field2HmacHolders HMAC holders for field 2
	 * @param <T> result type
	 * @return the optional result
	 */
	public static <T> Optional<T> executeOptionalReturningQuadFunction(QuadFunction<String, String, String, String, Optional<T>> repositorySearchFunction,
																	   List<HmacHolder> field1HmacHolders, List<HmacHolder> field2HmacHolders) {
		Optional<T> result = repositorySearchFunction.apply(field1HmacHolders.get(0).getValue(), field1HmacHolders.get(0).getValue(),
			field2HmacHolders.get(0).getValue(), field2HmacHolders.get(0).getValue());
		if (result.isEmpty() && field1HmacHolders.size() == 2 && field2HmacHolders.size() == 2) {
			result = repositorySearchFunction.apply(field1HmacHolders.get(1).getValue(), field1HmacHolders.get(1).getValue(),
				field2HmacHolders.get(1).getValue(), field2HmacHolders.get(1).getValue());
		}
		return result;
	}

	/**
	 * Executes a repository search that returns a list using two fields with up to two HMAC values each.
	 *
	 * @param repositorySearchFunction the repository search function
	 * @param field1HmacHolders HMAC holders for field 1
	 * @param field2HmacHolders HMAC holders for field 2
	 * @param <T> result type
	 * @return the results list
	 */
	public static <T> List<T> executeListReturningQuadFunction(QuadFunction<String, String, String, String, List<T>> repositorySearchFunction,
															   List<HmacHolder> field1HmacHolders, List<HmacHolder> field2HmacHolders) {
		List<T> results = repositorySearchFunction.apply(field1HmacHolders.get(0).getValue(), field1HmacHolders.get(0).getValue(),
			field2HmacHolders.get(0).getValue(), field2HmacHolders.get(0).getValue());
		if (field1HmacHolders.size() == 2 && field2HmacHolders.size() == 2) {
			results.addAll(repositorySearchFunction.apply(field1HmacHolders.get(1).getValue(), field1HmacHolders.get(1).getValue(),
				field2HmacHolders.get(1).getValue(), field2HmacHolders.get(1).getValue()));
		}
		return results;
	}

	public interface QuadFunction<P1, P2, P3, P4, R> {
		/**
		 * Applies the function to the supplied values.
		 *
		 * @param value1 the first value
		 * @param value2 the second value
		 * @param value3 the third value
		 * @param value4 the fourth value
		 * @return the result
		 */
		R apply(P1 value1, P2 value2, P3 value3, P4 value4);
	}
}
