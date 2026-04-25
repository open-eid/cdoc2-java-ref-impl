package ee.cyber.cdoc2.services;

import ee.cyber.cdoc2.client.rpserver.Cdoc2RpClient;
import ee.cyber.cdoc2.config.Cdoc2RpClientConfiguration;

public class Cdoc2RpClientServiceConfiguration implements ServiceConfiguration<Cdoc2RpClient,
    Cdoc2RpClientConfiguration> {
    Cdoc2RpClientConfiguration conf;

    Cdoc2RpClientServiceConfiguration(Cdoc2RpClientConfiguration conf) {
        this.conf = conf;
    }
    @Override
    public ServiceFac<Cdoc2RpClient, Cdoc2RpClientConfiguration> factory() {
//        return SIDClientService.factory();
        return null;
    }

    @Override
    public Cdoc2RpClientConfiguration getConfiguration() {
        return conf;
    }

}
