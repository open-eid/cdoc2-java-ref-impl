package ee.cyber.cdoc2.services;

/**
 * @param <S> service
 * @param <C> service configuration
 */
public interface ServiceConfiguration<S, C> {

    // ServiceFac that can create the service from this configuration
    ServiceFac<S, C> factory();

    // actual configuration
    C getConfiguration();

}
