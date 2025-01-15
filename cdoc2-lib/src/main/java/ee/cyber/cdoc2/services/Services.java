package ee.cyber.cdoc2.services;

import jakarta.annotation.Nullable;

/**
 * Interface that allows to retrieve previously registered services by their type and optional name.
 */
public interface Services {

    /**
     * Retrieves a service instance by class and name.
     *
     * @param clazz The class type of the service.
     * @param name  The optional name for the service instance.
     * @param <T>   The type of the service to retrieve.
     * @return The service instance.
     */
    <T> T get(Class<T> clazz, @Nullable String name);

    /**
     * @param clazz The class type of the service.
     * @param name  The optional name for the service instance.
     */
    boolean hasService(Class clazz, @Nullable String name);

    /**
     * Retrieves a service instance by class.
     *
     * @param clazz The class type of the service.
     * @param <T>   The type of the service to retrieve.
     * @return The service instance.
     */
    default <T> T get(Class<T> clazz) {
        return get(clazz, null);
    }

    default boolean hasService(Class clazz) {
        return hasService(clazz, null);
    }

}
