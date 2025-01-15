package ee.cyber.cdoc2.services;


/**
 * Template magic to create {@link ee.cyber.cdoc2.services.Service} objects easily. Example:
 * <pre>
 * {@code
 *   SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();
 *   // SmartIdClient has following constructor: SmartIdClient(SmartIdClientConfiguration)
 *   Service<SmartIdClient, SmartIdClientConfiguration> service =
 *             ServiceTemplate.service(sidConf, SmartIdClient::new);
 *   SmartIdClient smartIdClient = service.getDelegate();
 *   SmartIDClientConfiguration sidConf = service.getConfiguration();
 *  }
 * </pre>
 *           
 */
public final class ServiceTemplate {

    private ServiceTemplate() {
    }

    public static <S, C> ServiceConfiguration<S, C> configuration(C config, ServiceFac<S, C> fac) {
        return new ServiceConfiguration<S, C>() {
            @Override
            public ServiceFac<S, C> factory() {
                return fac;
            }

            @Override
            public C getConfiguration() {
                return config;
            }
        };
    }

    public static <S, C> Service<S, C> serviceFromFactory(C config, ServiceFac<S, C> factory) {
        ServiceConfiguration<S, C> serviceConf = configuration(config, factory);
        ServiceFac<S, C> fac = serviceConf.factory();
        return fac.create(serviceConf);
    }

    /**
     *
     * @param config configuration of the service (delegate)
     * @param delegateFactory function to create the delegate, for example <code>SmartIdClient::new</code>
     * @return
     * @param <S> service (delegate), for example SmartIdClient
     * @param <C> configuration, for example SmartIdClientConfiguration
     */
    public static <S, C> Service<S, C> service(C config,  java.util.function.Function<C, S> delegateFactory) {
        return ServiceTemplate.serviceFromFactory(config, serviceConfiguration ->
                new ServiceTemplate.GenericService<>(serviceConfiguration, delegateFactory));
    }

    // A generic implementation of the Service interface to allow creation of Service objects from configuration
    public static class GenericService<S, C> implements Service<S, C> {
        // The configuration object for the service.
        private final C configuration;

        // The actual service delegate instance.
        private final S delegate;

        /**
         * Constructor for GenericService.
         * @param config          The service configuration C
         * @param delegateFactory A function to create the delegate instance using the configuration C
         *                        (takes C configuration as parameter and returns S object)
         */
        public GenericService(ServiceConfiguration<S, C> config, java.util.function.Function<C, S> delegateFactory) {
            // Initialize the configuration from the provided config object.
            this.configuration = config.getConfiguration();
            // Use the provided factory function to create the delegate instance.
            this.delegate = delegateFactory.apply(this.configuration);
        }

        /**
         * Returns the configuration associated with this service.
         * @return The service configuration.
         */
        @Override
        public C getConfiguration() {
            return configuration;
        }

        /**
         * Returns the service delegate instance.
         * @return The delegate instance.
         */
        @Override
        public S getDelegate() {
            return delegate;
        }
    }

}
