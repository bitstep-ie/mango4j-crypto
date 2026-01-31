package ie.bitstep.mango.crypto.functions;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RotationSupportedRepositoryFunctionsTest {

	private static final String HMAC_VALUE_1 = "hmacValue1";
	private static final String HMAC_VALUE_2 = "hmacValue2";
	private static final String HMAC_VALUE_3 = "hmacValue3";
	private static final String HMAC_VALUE_4 = "hmacValue4";
	private static final String LIST_1_VALUE_A = "list1a";
	private static final String LIST_1_VALUE_B = "list1b";
	private static final String LIST_2_VALUE_A = "list2a";
	private static final String LIST_2_VALUE_B = "list2b";

	private List<String> testArrayList1;
	private List<String> testArrayList2;
	private final HmacHolder hmacHolder1 = new HmacHolder(TEST_CRYPTO_KEY_2, HMAC_VALUE_1);
	private final HmacHolder hmacHolder2 = new HmacHolder(TEST_CRYPTO_KEY_2, HMAC_VALUE_2);
	private final HmacHolder hmacHolder3 = new HmacHolder(TEST_CRYPTO_KEY_2, HMAC_VALUE_3);
	private final HmacHolder hmacHolder4 = new HmacHolder(TEST_CRYPTO_KEY_2, HMAC_VALUE_4);

	private final BiFunction<String, String, List<String>> testListReturningBiFunction = (parameter1, parameter2) -> {
		if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)) {
			return testArrayList1;
		} else if (HMAC_VALUE_2.equals(parameter1) && HMAC_VALUE_2.equals(parameter2)) {
			return testArrayList2;
		}
		return new ArrayList<>();
	};

	private static final BiFunction<String, String, Optional<String>> TEST_OPTIONAL_RETURNING_BI_FUNCTION = (parameter1, parameter2) -> {
		if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)) {
			return Optional.of(LIST_1_VALUE_A);
		} else if (HMAC_VALUE_2.equals(parameter1) && HMAC_VALUE_2.equals(parameter2)) {
			return Optional.of(LIST_1_VALUE_B);
		}
		return Optional.empty();
	};

	private final RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, List<String>> testListReturningQuadFunction
		= (parameter1, parameter2, parameter3, parameter4) -> {
		if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)) {
			return testArrayList1;
		} else if (HMAC_VALUE_2.equals(parameter1) && HMAC_VALUE_2.equals(parameter2)) {
			return testArrayList2;
		}
		return new ArrayList<>();
	};

	private static final RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> TEST_OPTIONAL_RETURNING_QUAD_FUNCTION
		= (parameter1, parameter2, parameter3, parameter4) -> {
		if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)) {
			return Optional.of(LIST_1_VALUE_A);
		} else if (HMAC_VALUE_2.equals(parameter1) && HMAC_VALUE_2.equals(parameter2)) {
			return Optional.of(LIST_1_VALUE_B);
		}
		return Optional.empty();
	};

	@BeforeEach
	void setup() {
		testArrayList1 = new ArrayList<>();
		testArrayList1.add(LIST_1_VALUE_A);
		testArrayList1.add(LIST_1_VALUE_B);

		testArrayList2 = new ArrayList<>();
		testArrayList2.add(LIST_2_VALUE_A);
		testArrayList2.add(LIST_2_VALUE_B);
	}

	@Test
	void constructor() throws Exception {
		Constructor<RotationSupportedRepositoryFunctions> constructor = RotationSupportedRepositoryFunctions.class.getDeclaredConstructor();
		constructor.setAccessible(true);

		assertThatThrownBy(constructor::newInstance).hasCauseInstanceOf(AssertionError.class);
	}

	@Test
	void executeListReturningBiFunctionWithSingleHmacHolder() {
		List<String> results = RotationSupportedRepositoryFunctions.executeListReturningBiFunction(testListReturningBiFunction,
			List.of(hmacHolder1));

		assertThat(results)
			.filteredOn(LIST_1_VALUE_A::equals).isNotEmpty();
		assertThat(results)
			.filteredOn(LIST_1_VALUE_B::equals).isNotEmpty();
		assertThat(results)
			.filteredOn(LIST_2_VALUE_A::equals).isEmpty();
		assertThat(results)
			.filteredOn(LIST_2_VALUE_B::equals).isEmpty();
	}

	@Test
	void executeListReturningBiFunctionWithTwoHmacHolders() {
		List<String> results = RotationSupportedRepositoryFunctions.executeListReturningBiFunction(testListReturningBiFunction,
			List.of(hmacHolder1, hmacHolder2));

		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_A)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_B)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_A)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_B)).isNotEmpty();
	}

	@Test
	void executeOptionalReturningBiFunctionWithSingleHmacHolder() {
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningBiFunction(TEST_OPTIONAL_RETURNING_BI_FUNCTION,
			List.of(hmacHolder1));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_A));
	}

	@Test
	void executeOptionalReturningBiFunctionWithSingleHmacHolderNoResults() {
		BiFunction<String, String, Optional<String>> testOptionalReturningBiFunction = (parameter1, parameter2) -> Optional.empty();
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningBiFunction(testOptionalReturningBiFunction,
			List.of(hmacHolder1));

		assertThat(result).isNotPresent();
	}

	@Test
	void executeOptionalReturningBiFunctionWithTwoHmacHoldersButFirstFunctionCallReturnsSomething() {
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningBiFunction(TEST_OPTIONAL_RETURNING_BI_FUNCTION,
			List.of(hmacHolder1, hmacHolder2));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_A));
	}

	@Test
	void executeOptionalReturningBiFunctionWithTwoHmacHoldersButFirstFunctionCallDoesNotReturnAnything() {
		BiFunction<String, String, Optional<String>> testOptionalReturningBiFunction = (parameter1, parameter2) -> {
			if (HMAC_VALUE_2.equals(parameter1) && HMAC_VALUE_2.equals(parameter2)) {
				return Optional.of(LIST_1_VALUE_B);
			}
			return Optional.empty();
		};
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningBiFunction(testOptionalReturningBiFunction,
			List.of(hmacHolder1, hmacHolder2));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_B));
	}

	@Test
	void executeListReturningQuadFunctionWithSingleHmacHolder() {
		List<String> results = RotationSupportedRepositoryFunctions.executeListReturningQuadFunction(testListReturningQuadFunction,
			List.of(hmacHolder1), List.of(hmacHolder2));

		assertThat(results)
			.filteredOn(LIST_1_VALUE_A::equals).isNotEmpty();
		assertThat(results)
			.filteredOn(LIST_1_VALUE_B::equals).isNotEmpty();
		assertThat(results)
			.filteredOn(LIST_2_VALUE_A::equals).isEmpty();
		assertThat(results)
			.filteredOn(LIST_2_VALUE_B::equals).isEmpty();
	}

	@Test
	void executeListReturningQuadFunctionWithTwoHmacHolders() {
		List<String> results = RotationSupportedRepositoryFunctions.executeListReturningQuadFunction(testListReturningQuadFunction,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3, hmacHolder4));

		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_A)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_B)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_A)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_B)).isNotEmpty();
	}

	@Test
	void executeListReturningQuadFunctionWithTwoHmacHoldersForFirstParameter() {
		List<String> results = RotationSupportedRepositoryFunctions.executeListReturningQuadFunction(testListReturningQuadFunction,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3));

		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_A)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_B)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_A)).isEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_B)).isEmpty();
	}

	@Test
	void executeListReturningQuadFunctionWithTwoHmacHoldersForSecondParameter() {
		List<String> results = RotationSupportedRepositoryFunctions.executeListReturningQuadFunction(testListReturningQuadFunction,
			List.of(hmacHolder1), List.of(hmacHolder3, hmacHolder4));

		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_A)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_1_VALUE_B)).isNotEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_A)).isEmpty();
		assertThat(results)
			.filteredOn(s -> s.equals(LIST_2_VALUE_B)).isEmpty();
	}

	@Test
	void executeOptionalReturningQuadFunctionWithSingleHmacHolderReturnsSomething() {
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(TEST_OPTIONAL_RETURNING_QUAD_FUNCTION,
			List.of(hmacHolder1), List.of(hmacHolder2));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_A));
	}

	@Test
	void executeOptionalReturningQuadFunctionWithSingleHmacHolderNoResults() {
		RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> testOptionalReturningQuadFunction =
			(parameter1, parameter2, parameter3, parameter4) -> Optional.empty();
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(testOptionalReturningQuadFunction,
			List.of(hmacHolder1), List.of(hmacHolder2));

		assertThat(result).isNotPresent();
	}

	@Test
	void executeOptionalReturningQuadFunctionWithTwoHmacHoldersButFirstFunctionCallReturnsSomething() {
		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(TEST_OPTIONAL_RETURNING_QUAD_FUNCTION,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3, hmacHolder4));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_A));
	}

	@Test
	void executeOptionalReturningQuadFunctionWithTwoHmacHoldersButFirstFunctionCallDoesNotReturnAnything() {
		RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> testOptionalReturningQuadFunction =
			(parameter1, parameter2, parameter3, parameter4) -> {
				if (HMAC_VALUE_2.equals(parameter1) && HMAC_VALUE_2.equals(parameter2)
					&& HMAC_VALUE_4.equals(parameter3) && HMAC_VALUE_4.equals(parameter4)) {
					return Optional.of(LIST_1_VALUE_B);
				}
				return Optional.empty();
			};

		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(testOptionalReturningQuadFunction,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3, hmacHolder4));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_B));
	}

	@Test
	void executeOptionalReturningQuadFunctionFirstParameterWithTwoHmacHoldersAndSecondParameterWithOneHmacHolderButFirstFunctionCallDoesNotReturnAnything() {
		RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> testOptionalReturningQuadFunction =
			(parameter1, parameter2, parameter3, parameter4) -> {
				if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)
					&& HMAC_VALUE_4.equals(parameter3) && HMAC_VALUE_4.equals(parameter4)) {
					return Optional.of(LIST_1_VALUE_B);
				} else
					return Optional.empty();
			};

		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(testOptionalReturningQuadFunction,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3));

		assertThat(result).isNotPresent();
	}

	@Test
	void executeOptionalReturningQuadFunctionFirstParameterWithOneHmacHolderAndSecondParameterWithTwoHmacHoldersButFirstFunctionCallDoesNotReturnAnything() {
		RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> testOptionalReturningQuadFunction =
			(parameter1, parameter2, parameter3, parameter4) -> {
				if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)
					&& HMAC_VALUE_4.equals(parameter3) && HMAC_VALUE_4.equals(parameter4)) {
					return Optional.of(LIST_1_VALUE_B);
				}
				return Optional.empty();
			};

		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(testOptionalReturningQuadFunction,
			List.of(hmacHolder1), List.of(hmacHolder3, hmacHolder4));

		assertThat(result).isNotPresent();
	}

	@Test
	void executeOptionalReturningQuadFunctionFirstParameterWithTwoHmacHoldersAndSecondParameterWithOneHmacHolderAndFirstFunctionCallReturnsSomething() {
		RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> testOptionalReturningQuadFunction =
			(parameter1, parameter2, parameter3, parameter4) -> {
				if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)
					&& HMAC_VALUE_3.equals(parameter3) && HMAC_VALUE_3.equals(parameter4)) {
					return Optional.of(LIST_1_VALUE_B);
				}
				return Optional.empty();
			};

		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(testOptionalReturningQuadFunction,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_B));
	}

	@Test
	void executeOptionalReturningQuadFunctionFirstParameterWithOneHmacHolderAndSecondParameterWithTwoHmacHoldersButFirstFunctionCallReturnsSomething() {
		RotationSupportedRepositoryFunctions.QuadFunction<String, String, String, String, Optional<String>> testOptionalReturningQuadFunction =
			(parameter1, parameter2, parameter3, parameter4) -> {
				if (HMAC_VALUE_1.equals(parameter1) && HMAC_VALUE_1.equals(parameter2)
					&& HMAC_VALUE_3.equals(parameter3) && HMAC_VALUE_3.equals(parameter4)) {
					return Optional.of(LIST_1_VALUE_B);
				}
				return Optional.empty();
			};

		Optional<String> result = RotationSupportedRepositoryFunctions.executeOptionalReturningQuadFunction(testOptionalReturningQuadFunction,
			List.of(hmacHolder1, hmacHolder2), List.of(hmacHolder3));

		assertThat(result).isEqualTo(Optional.of(LIST_1_VALUE_B));
	}
}