package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;


/**
 * @link{Service} that
 */
public class SIDClientService implements Service<SmartIdClient, SmartIdClientConfiguration> {

    SmartIdClientConfiguration config;
    SmartIdClient client;

    protected SIDClientService(ServiceConfiguration<SmartIdClient, SmartIdClientConfiguration> conf) {
        config = conf.getConfiguration();
        client = new SmartIdClient(config);
    }

    @Override
    public SmartIdClientConfiguration getConfiguration() {
        return this.config;
    }

    @Override
    public SmartIdClient getDelegate() {
        return client;
    }

    /**
     * Service factory that creates {@link ServiceFac<SmartIdClient, SmartIdClientConfiguration>}
     * @return
     */
    public static ServiceFac<SmartIdClient, SmartIdClientConfiguration> factory() {
        return new ServiceFac<SmartIdClient, SmartIdClientConfiguration>() {
            @Override
            public Service<SmartIdClient, SmartIdClientConfiguration> create(
                ServiceConfiguration<SmartIdClient, SmartIdClientConfiguration> config) {
                    return new SIDClientService(config);
            }
        };
    }

}
