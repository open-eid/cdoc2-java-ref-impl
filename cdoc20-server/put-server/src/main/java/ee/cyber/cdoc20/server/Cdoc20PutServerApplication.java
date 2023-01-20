package ee.cyber.cdoc20.server;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@Configuration
@EnableJpaAuditing
@Slf4j
public class Cdoc20PutServerApplication implements CommandLineRunner {

    @Autowired
    BuildProperties buildProperties;


    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(Cdoc20PutServerApplication.class);
        // capture startup events for startup actuator endpoint
        app.setApplicationStartup(MonitoringUtil.getApplicationStartupInfo());
        app.run(args);
    }

    @Override
    public void run(final String... args) throws Exception {
        log.info("CDOC 2.0 key capsule put-server is running.");
    }

    @Bean
    MeterRegistryCustomizer<MeterRegistry> metricsCommonTags() {
        // 'application' tag for all metrics
        return registry -> registry.config()
                .commonTags("application", buildProperties.getArtifact() //cdoc20-put-server
        );
    }

}

