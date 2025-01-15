package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.ClientConfigurationUtil;
import ee.cyber.cdoc2.client.KeyShareClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.config.KeySharesConfiguration;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import static ee.cyber.cdoc2.services.ThrowingFunction.suppressEx;
import static ee.cyber.cdoc2.smartid.SmartIdClientTest.getDemoEnvConfiguration;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;


class ServicesTest {

    private static final Logger log = LoggerFactory.getLogger(ServicesTest.class);

    @Test
    void testServicesSimple() {
        ServiceConfiguration<SmartIdClient, SmartIdClientConfiguration> conf =
            new SIDServiceConfiguration(getDemoEnvConfiguration());
        ServiceFac<SmartIdClient, SmartIdClientConfiguration> fac = conf.factory();
        Service<SmartIdClient, SmartIdClientConfiguration> service = fac.create(conf);
        SmartIdClient client = service.getDelegate();

        assertNotNull(client);
    }

    @Test
    void testServicesRegisterService() throws Exception {

//        ServiceConfiguration<SmartIdClient, SmartIdClientConfiguration> conf =
//            new SIDServiceConfiguration(getDemoEnvConfiguration());

        SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();

        Service<SmartIdClient, SmartIdClientConfiguration> sidService =
            ServiceTemplate.service(sidConf, SmartIdClient::new);

        ThrowingFunction<KeySharesConfiguration, KeyShareClientFactory> keyShareClientFactoryFunc =
            config -> KeySharesClientHelper.createFactory(config);

        var f = suppressEx(keyShareClientFactoryFunc);

        Service<KeyShareClientFactory, KeySharesConfiguration> keySharesFactoryService =
            ServiceTemplate.service(ClientConfigurationUtil.initKeySharesConfiguration(),
                suppressEx(config -> KeySharesClientHelper.createFactory(config)));

        Services services = new ServicesBuilder()
            .registerService(SmartIdClient.class, sidService, null)
            .registerService(KeyShareClientFactory.class, keySharesFactoryService, null)
            .build();
        SmartIdClient client = services.get(SmartIdClient.class); //throws IllegalArgumentException if not found

        // if no exception, we have a client. Keep linters happy
        assertNotNull(client);
        assertNotNull(services.get(KeyShareClientFactory.class));
    }

    @Test
    void shouldThrowWithNonMatchingParams() {
        SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();

        Service<SmartIdClient, SmartIdClientConfiguration> sidService =
            ServiceTemplate.service(sidConf, SmartIdClient::new);

        // Service must be registered with registerService
        assertThrows(IllegalArgumentException.class, () -> new ServicesBuilder()
            .register(SmartIdClient.class, sidService, null));

        new ServicesBuilder()
            .registerService(SmartIdClient.class, sidService, null);
    }

    @Test
    void testServiceDecoratorConfiguration() {

        SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();
        ServiceConfiguration<SmartIdClient, SmartIdClientConfiguration> serviceConf =
            ServiceTemplate.configuration(sidConf, conf -> new Service<SmartIdClient, SmartIdClientConfiguration>() {

                @Override
                public SmartIdClientConfiguration getConfiguration() {
                    log.info("getConfiguration()");
                    return conf.getConfiguration();
                }

                @Override
                public SmartIdClient getDelegate() {
                    log.info("getDelegate()");
                    return new SmartIdClient(conf.getConfiguration());
                }
            });

        assertNotNull(serviceConf);

        SmartIdClientConfiguration smartIdClientConfiguration = serviceConf.getConfiguration();
        assertNotNull(smartIdClientConfiguration);
        assertNotNull(smartIdClientConfiguration.getHostUrl());

        log.debug("SID URL: {}", smartIdClientConfiguration.getHostUrl());
    }

    @Test
    void testServiceDecoratorServiceFromFactory() {

        SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();

        // lambda to implement ServiceFac::create method
        // full signature: Service<S, C> create(ServiceConfigurationExt<S,C> config)
        Service<SmartIdClient, SmartIdClientConfiguration> service =
            ServiceTemplate.serviceFromFactory(sidConf, config -> new Service<>() { //implement

                // initialize SmartIdClient once
                private final SmartIdClient smartIdClient = new SmartIdClient(sidConf);

                @Override
                public SmartIdClientConfiguration getConfiguration() {
                    return sidConf;
                }

                @Override
                public SmartIdClient getDelegate() {
                    return smartIdClient;
                }
            });

        checkService(service);
    }

    @Test
    void testServiceDecoratorGenericService() {

        SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();

        Service<SmartIdClient, SmartIdClientConfiguration> service =
            ServiceTemplate.serviceFromFactory(sidConf,
                config -> new ServiceTemplate.GenericService<>(config, SmartIdClient::new));

        checkService(service);
    }

    @Test
    void testServiceDecoratorService() {

        SmartIdClientConfiguration sidConf = getDemoEnvConfiguration();

        Service<SmartIdClient, SmartIdClientConfiguration> service =
            ServiceTemplate.service(sidConf, SmartIdClient::new);

        checkService(service);
    }

    private static void checkService(Service<SmartIdClient, SmartIdClientConfiguration> service) {
        assertNotNull(service);

        SmartIdClientConfiguration smartIdClientConfiguration = service.getConfiguration();
        assertNotNull(smartIdClientConfiguration);
        assertNotNull(smartIdClientConfiguration.getHostUrl());
        log.debug("SID URL: {}", smartIdClientConfiguration.getHostUrl());

        SmartIdClient smartIdClient = service.getDelegate();
        assertNotNull(smartIdClient);

        // check that client is not created twice, but cached client is used
        assertSame(smartIdClient, service.getDelegate());
    }
}
