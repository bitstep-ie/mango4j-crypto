package ie.bitstep.mango.crypto.testdata.annotations;

import ie.bitstep.mango.crypto.annotations.strategies.HmacStrategyToUse;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@HmacStrategyToUse(ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies.InvalidCustomHmacStrategyNoDefaultConstructor.class)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Inherited
public @interface InvalidCustomHmacStrategyNoDefaultConstructor {
}
