package ee.cyber.cdoc2.services;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.cyber.cdoc2.ClientConfigurationUtil;
import ee.cyber.cdoc2.client.KeySharesClientFactory;
import ee.cyber.cdoc2.client.KeySharesClientHelper;
import ee.cyber.cdoc2.client.rpserver.Cdoc2RpClient;
import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;
import ee.cyber.cdoc2.config.KeySharesConfiguration;

import static ee.cyber.cdoc2.services.ThrowingFunction.suppressEx;
import static org.junit.jupiter.api.Assertions.*;


class ServicesTest {

    private static final Logger log = LoggerFactory.getLogger(ServicesTest.class);

    @Test
    void testServicesRegisterService() {
        Cdoc2RpClientConfiguration rpConf =
            ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();

        Service<Cdoc2RpClient, Cdoc2RpClientConfiguration> rpService =
            ServiceTemplate.service(rpConf, Cdoc2RpClient::new);

        Service<KeySharesClientFactory, KeySharesConfiguration> keySharesFactoryService =
            ServiceTemplate.service(ClientConfigurationUtil.initKeySharesTestEnvConfiguration(),
                suppressEx(config -> KeySharesClientHelper.createFactory(config)));

        Services services = new ServicesBuilder()
            .registerService(Cdoc2RpClient.class, rpService, null)
            .registerService(KeySharesClientFactory.class, keySharesFactoryService, null)
            .build();
        Cdoc2RpClient client = services.get(Cdoc2RpClient.class); //throws IllegalArgumentException if not found

        // if no exception, we have a client. Keep linters happy
        assertNotNull(client);
        assertNotNull(services.get(KeySharesClientFactory.class));
    }

    @Test
    void shouldThrowWithNonMatchingParams() {
        Cdoc2RpClientConfiguration rpConf =
            ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();

        Service<Cdoc2RpClient, Cdoc2RpClientConfiguration> sidService =
            ServiceTemplate.service(rpConf, Cdoc2RpClient::new);

        // Service must be registered with registerService
        assertThrows(IllegalArgumentException.class, () -> new ServicesBuilder()
            .register(Cdoc2RpClient.class, sidService, null));

        new ServicesBuilder()
            .registerService(Cdoc2RpClient.class, sidService, null);
    }

    @Test
    void testServiceDecoratorConfiguration() {
        Cdoc2RpClientConfiguration rpConf =
            ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();

        ServiceConfiguration<Cdoc2RpClient, Cdoc2RpClientConfiguration> serviceConf =
            ServiceTemplate.configuration(rpConf, conf -> new Service<Cdoc2RpClient, Cdoc2RpClientConfiguration>() {

                @Override
                public Cdoc2RpClientConfiguration getConfiguration() {
                    log.info("getConfiguration()");
                    return conf.getConfiguration();
                }

                @Override
                public Cdoc2RpClient getDelegate() {
                    log.info("getDelegate()");
                    return new Cdoc2RpClient(conf.getConfiguration());
                }
            });

        assertNotNull(serviceConf);

        Cdoc2RpClientConfiguration rpClientConfiguration = serviceConf.getConfiguration();
        assertNotNull(rpClientConfiguration);
        assertNotNull(rpClientConfiguration.getHostUrl());

        log.debug("SID URL: {}", rpClientConfiguration.getHostUrl());
    }

    @Test
    void testServiceDecoratorServiceFromFactory() {
        Cdoc2RpClientConfiguration rpConf =
            ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();

        // lambda to implement ServiceFac::create method
        // full signature: Service<S, C> create(ServiceConfigurationExt<S,C> config)
        Service<Cdoc2RpClient, Cdoc2RpClientConfiguration> service =
            ServiceTemplate.serviceFromFactory(rpConf, config -> new Service<>() { //implement

                // initialize Cdoc2RpClient once
                private final Cdoc2RpClient rpClient = new Cdoc2RpClient(rpConf);

                @Override
                public Cdoc2RpClientConfiguration getConfiguration() {
                    return rpConf;
                }

                @Override
                public Cdoc2RpClient getDelegate() {
                    return rpClient;
                }
            });

        checkService(service);
    }

    @Test
    void testServiceDecoratorGenericService() {
        Cdoc2RpClientConfiguration rpConf =
            ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();

        Service<Cdoc2RpClient, Cdoc2RpClientConfiguration> service =
            ServiceTemplate.serviceFromFactory(rpConf,
                config -> new ServiceTemplate.GenericService<>(config, Cdoc2RpClient::new));

        checkService(service);
    }

    @Test
    void testServiceDecoratorService() {
        Cdoc2RpClientConfiguration rpConf =
            ClientConfigurationUtil.getCdoc2RpClientDemoEnvConfiguration();

        Service<Cdoc2RpClient, Cdoc2RpClientConfiguration> service =
            ServiceTemplate.service(rpConf, Cdoc2RpClient::new);

        checkService(service);
    }

    private static void checkService(Service<Cdoc2RpClient, Cdoc2RpClientConfiguration> service) {
        assertNotNull(service);

        Cdoc2RpClientConfiguration rpClientConfiguration = service.getConfiguration();
        assertNotNull(rpClientConfiguration);
        assertNotNull(rpClientConfiguration.getHostUrl());
        assertNotNull(rpClientConfiguration.getCertificateLevel());
        log.debug("SID URL: {}", rpClientConfiguration.getHostUrl());

        Cdoc2RpClient rpClient = service.getDelegate();
        assertNotNull(rpClient);

        // check that client is not created twice, but cached client is used
        assertSame(rpClient, service.getDelegate());
    }
}
