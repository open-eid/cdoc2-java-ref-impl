package ee.cyber.cdoc2.server;

import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.stereotype.Component;

/**
 * Configure client authentication certificate revocation checking for mutual TLS
 */
@Component
@Slf4j
public class ClientAuthCertRevocationCustomizer implements TomcatConnectorCustomizer {
    //spring properties
    @Value("${cdoc2.ssl.client-auth.revocation-checks.enabled:true}")
    private boolean revocationCheckEnabled;

    @Override
    @SuppressWarnings("LineLength")
    public void customize(Connector connector) {
        //https://docs.oracle.com/en/java/javase/17/security/java-pki-programmers-guide.html#GUID-650D0D53-B617-4055-AFD3-AF5C2629CBBF
        // run with -Djava.security.debug="certpath" to produce detailed log
        // when client auth cert has AuthorityInfoAccess extension

        log.debug("Customizing {}", connector);
        log.debug("cdoc2.ssl.client-auth.revocation-checks.enabled={}", revocationCheckEnabled);

        if (revocationCheckEnabled) {
            log.info("Enabling OCSP revocation check for {}", connector);
            log.debug("Setting ocsp.enable=true");
            Security.setProperty("ocsp.enable", "true");
            System.setProperty("com.sun.security.enableAIAcaIssuers", "true");

            // Optional revocation related properties
            ////https://docs.oracle.com/en/java/javase/17/security/java-pki-programmers-guide.html#GUID-650D0D53-B617-4055-AFD3-AF5C2629CBBF
            //System.setProperty("com.sun.security.enableCRLDP", "true");
            //System.setProperty("com.sun.security.crl.timeout", "15");
            //System.setProperty("com.sun.security.crl.readtimeout", "15");
            //System.setProperty("com.sun.security.ocsp.timeout", "15");
            //System.setProperty("jdk.security.certpath.OCSPNonce", "true");

            //OCSP checks are done by
            //sun.security.provider.certpath.OCSP class

            Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
            SSLHostConfig[] sslConfigs = protocol.findSslHostConfigs();
            for (SSLHostConfig sslHostConfig : sslConfigs) {
                //https://tomcat.apache.org/tomcat-10.1-doc/config/http.html#SSL_Support_-_SSLHostConfig
                sslHostConfig.setRevocationEnabled(true);
            }
        }
        log.debug("ocsp.enable={}", Security.getProperty("ocsp.enable"));
    }
}
