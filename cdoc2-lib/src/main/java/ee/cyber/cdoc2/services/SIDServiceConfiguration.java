package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.client.smartid.SmartIdClient;
import ee.cyber.cdoc2.config.SmartIdClientConfiguration;


public class SIDServiceConfiguration implements ServiceConfiguration<SmartIdClient, SmartIdClientConfiguration> {
    SmartIdClientConfiguration conf;

    SIDServiceConfiguration(SmartIdClientConfiguration conf) {
        this.conf = conf;
    }
    @Override
    public ServiceFac<SmartIdClient, SmartIdClientConfiguration> factory() {
        return SIDClientService.factory();
    }

    @Override
    public SmartIdClientConfiguration getConfiguration() {
        return conf;
    }

}
