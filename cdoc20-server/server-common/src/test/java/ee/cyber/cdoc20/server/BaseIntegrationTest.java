package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.client.model.ServerEccDetails;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpa;
import ee.cyber.cdoc20.server.model.ServerEccDetailsJpaRepository;
import java.util.Base64;
import java.util.Optional;
import java.util.random.RandomGenerator;
import javax.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import static ee.cyber.cdoc20.server.Utils.MODEL_MAPPER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Starts server on https
// Starts PostgreSQL running on docker
@ExtendWith(SpringExtension.class)
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = { "management.server.port=0" }
)
@Testcontainers
@ContextConfiguration(initializers = BaseIntegrationTest.Initializer.class)
@Slf4j
abstract class BaseIntegrationTest {
    // start PostgreSQL on Docker container
    @Container
    protected static final PostgreSQLContainer postgresContainer = new PostgreSQLContainer("postgres:11.1")
        .withDatabaseName("integration-tests-db")
        .withUsername("sa")
        .withPassword("sa");

    static class Initializer
            implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        public void initialize(ConfigurableApplicationContext configurableApplicationContext) {
            TestPropertyValues.of(
                    "spring.datasource.url=" + postgresContainer.getJdbcUrl(),
                    "spring.datasource.username=" + postgresContainer.getUsername(),
                    "spring.datasource.password=" + postgresContainer.getPassword()
            ).applyTo(configurableApplicationContext.getEnvironment());
        }
    }

    @Value("https://localhost:${local.server.port}")
    protected String baseUrl;

    @Autowired
    protected ServerEccDetailsJpaRepository jpaRepository;

    @Test
    void contextLoads() {
        // tests that server is configured properly (no exceptions means success)
    }

    @Test
    void testJpaConstraints() {
        ServerEccDetailsJpa model = new ServerEccDetailsJpa();

        model.setEccCurve(1);
        model.setSenderPubKey("123");
        byte[] rnd = new byte[255];
        RandomGenerator.getDefault().nextBytes(rnd);
        model.setRecipientPubKey(Base64.getEncoder().encodeToString(rnd));

        Throwable cause = assertThrows(Throwable.class, () -> this.jpaRepository.save(model));

        //check that exception is or is caused by ConstraintViolationException
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }

        assertEquals(ConstraintViolationException.class, cause.getClass());
        assertNotNull(cause.getMessage());
        assertTrue(cause.getMessage().contains("'size must be between 0 and 132', propertyPath=recipientPubKey"));
    }

    @Test
    void testJpaSaveAndFindById() {
        assertTrue(postgresContainer.isRunning());

        // test that jpa is up and running (expect no exceptions)
        this.jpaRepository.count();

        ServerEccDetailsJpa model = new ServerEccDetailsJpa();
        model.setEccCurve(1);

        model.setRecipientPubKey("123");
        model.setSenderPubKey("345");
        ServerEccDetailsJpa saved = this.jpaRepository.save(model);

        assertNotNull(saved);
        assertNotNull(saved.getTransactionId());
        log.debug("Created {}", saved.getTransactionId());

        Optional<ServerEccDetailsJpa> retrieved = this.jpaRepository.findById(saved.getTransactionId());
        assertTrue(retrieved.isPresent());
        assertNotNull(retrieved.get().getTransactionId()); // transactionId was generated
        assertTrue(retrieved.get().getTransactionId().startsWith("SD"));
        assertNotNull(retrieved.get().getCreatedAt()); // createdAt field was filled
        log.debug("Retrieved {}", retrieved.get());
    }

    /**
     * Saves the capsule in the database
     * @param dto the capsule dto
     * @return the saved capsule
     */
    protected ServerEccDetailsJpa saveCapsule(ServerEccDetails dto) {
        return this.jpaRepository.save(MODEL_MAPPER.map(dto, ServerEccDetailsJpa.class));
    }
}
