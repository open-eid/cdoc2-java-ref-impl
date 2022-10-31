package ee.cyber.cdoc20.server;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@Configuration
@EnableJpaAuditing
@Slf4j
public class Cdoc20PutServerApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(Cdoc20PutServerApplication.class, args);
    }

    @Override
    public void run(final String... args) throws Exception {
        log.info("CDOC 2.0 key capsule put-server is running.");
    }
}
