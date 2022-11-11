package ee.cyber.cdoc20.server;

import lombok.SneakyThrows;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import static ee.cyber.cdoc20.server.TestData.getKeysDirectory;

/**
 * Test configuration
 */
@Configuration
public class TestingConfiguration {

    /**
     * @param builder the REST template builder
     * @return a REST template that trusts all hosts it connects to
     */
    @Bean(name = "trustAllNoClientAuth")
    @SneakyThrows
    public RestTemplate getTrustAllRestTemplate(RestTemplateBuilder builder) {
        SSLContext sslContext = SSLContextBuilder
            .create()
            .loadTrustMaterial(new TrustAllStrategy())
            .build();

        var client = HttpClients.custom()
            .setSSLContext(sslContext)
            .build();

        return builder
            .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
            .build();
    }

    /**
     * @param builder the REST template builder
     * @return a REST template with client authentication and trusts all hosts strategy
     */
    @Bean(name = "trustAllWithClientAuth")
    @SneakyThrows
    public RestTemplate getTrustAllWithClientAuthRestTemplate(RestTemplateBuilder builder) {
        SSLContext sslContext = SSLContextBuilder
            .create()
            .loadTrustMaterial(new TrustAllStrategy())
            .loadKeyMaterial(
                getKeysDirectory().resolve("rsa/client-rsa-2048.p12").toFile(),
                "passwd".toCharArray(),
                "passwd".toCharArray()
            )
            .build();

        var client = HttpClients.custom()
            .setSSLContext(sslContext)
            .build();

        return builder
            .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
            .build();
    }
}
