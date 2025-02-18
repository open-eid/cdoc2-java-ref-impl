package ee.cyber.cdoc2.services;

import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Default implementation to create {@link ee.cyber.cdoc2.services.Services} instances.
 */
public class ServicesBuilder {

    private static final Logger log = LoggerFactory.getLogger(ServicesBuilder.class);
    private final Map<String, Object> services = new HashMap<>();

    /**
     * Registers a service instance with its class and optional name.
     * 
     * @param type The service type. Same type is later used as parameter for {@link Services#get(Class)} ()}
     * @param delegate The client instance.
     * @param name   The optional name for the client instance.
     * @param <S>    The delegate of the actual service (ex)
     */
    public <S> ServicesBuilder register(Class type, S delegate, @Nullable String name) {
        log.debug("register {} {} {}", type, delegate, name);
        Objects.requireNonNull(type);
        Objects.requireNonNull(delegate, "Service instance must not be null");
        if (!type.isInstance(delegate)) {
            throw new IllegalArgumentException("Service " + delegate + " is not instance of " + type);
        }
        String key = generateKey(type, name);
        services.put(key, delegate);
        return this;
    }

    public <S, C> ServicesBuilder registerUsingConfig(
        Class type,
        ServiceConfiguration<S, C> config,
        @Nullable String name) {

        Service<S, C> service = config.factory().create(config);
        S serviceDelegate = service.getDelegate();
        this.register(type, serviceDelegate, name);
        return this;
    }

    public <S, C> ServicesBuilder registerService(Class type, Service<S, C> service, @Nullable String name) {
        log.debug("registerService {} {} {}", type, service, service.getDelegate());
        // Retrieve generic type information from the anonymous subclass

        this.register(type, service.getDelegate(), name);
        return this;
    }

    /**
     * Create immutable {@link ee.cyber.cdoc2.services.Services} instance from registered services
     * @return {@link ee.cyber.cdoc2.services.Services}
     */
    public Services build() {
        final Map<String, Object> unmodifiableMap = Collections.unmodifiableMap(services);
        return new Services() {
            @Override
            public <T> T get(Class<T> clazz, @Nullable String name) {
                return ServicesBuilder.get(unmodifiableMap, clazz, name);
            }

            @Override
            public boolean hasService(Class clazz, @Nullable String name) {
                return unmodifiableMap.containsKey(generateKey(clazz, name));
            }
        };
    }

    /**
     * Retrieves a service instance by class and name.
     *
     * @param services The map of services registered.
     * @param clazz The class type of the service.
     * @param name  The optional name for the service instance.
     * @param <T>   The type of the service to retrieve.
     * @return The service instance.
     * @throws IllegalArgumentException if service instance with class and name is not registered
     */
    private static <T> T get(Map<String, Object> services, Class<T> clazz, @Nullable String name) {
        String key = generateKey(clazz, name);
        Object service = services.get(key);
        if (service == null) {
            throw new IllegalArgumentException("No Service registered with name: " + key);
        }
        if (!clazz.isInstance(service)) {
            //should not really happen
            throw new ClassCastException("Registered service is not of type: " + clazz.getName());
        }
        return clazz.cast(service);
    }

    private static String generateKey(Class<?> clazz, @Nullable String name) {
        return clazz.getName() + "::" + (name != null ? name : "default");
    }

}
