package ee.cyber.cdoc2.services;

/**
 * Use {@link ServiceTemplate} to easily create {@link ee.cyber.cdoc2.services.Service} objects
 * @param <S> The Service delegate that provides the actual service
 * @param <C> Service configuration class
 */
public interface Service<S, C> {
    /**
     * Get the service instance
     * @return actual service
     */
    S getDelegate();

    C getConfiguration();
}
