package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.exceptions.UnCheckedException;
import java.util.function.Function;

/**
 * Generic functional interface that throws checked exceptions
 * @param <T> function parameter type
 * @param <R> function return type
 */
@FunctionalInterface
public interface ThrowingFunction<T, R> {
    R apply(T t) throws Exception;

    /**
     * Wrap checked exception throwing function into un-checked exception throwing function
     * @param function that throws checked exceptions
     * @return function that throws un-checked exceptions
     * @param <T> function parameter type
     * @param <R> function return type
     * @throws UnCheckedException when function threw an exception
     */
    static <T, R> Function<T, R> suppressEx(ThrowingFunction<T, R> function) throws UnCheckedException {
        return t -> {
            try {
                return function.apply(t);
            } catch (Exception e) {
                throw new UnCheckedException(e);  // Wrap as unchecked exception
            }
        };
    }
}
