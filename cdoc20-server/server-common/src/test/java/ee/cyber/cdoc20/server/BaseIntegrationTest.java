package ee.cyber.cdoc20.server;

import ee.cyber.cdoc20.client.model.Capsule;
import ee.cyber.cdoc20.server.model.db.KeyCapsuleDb;
import ee.cyber.cdoc20.server.model.db.KeyCapsuleRepository;
import java.util.Optional;
import javax.validation.ConstraintViolationException;
import lombok.SneakyThrows;
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

    // context path of the key capsule api
    protected static final String API_CONTEXT_PATH = "/key-capsules";

    @Value("https://localhost:${local.server.port}")
    protected String baseUrl;

    @Autowired
    protected KeyCapsuleRepository capsuleRepository;

    @Test
    void contextLoads() {
        // tests that server is configured properly (no exceptions means success)
    }

    @Test
    void testJpaConstraints() {
        KeyCapsuleDb model = new KeyCapsuleDb();

        model.setCapsuleType(KeyCapsuleDb.CapsuleType.SECP384R1);
        model.setPayload("123".getBytes());
        model.setRecipient(null);

        Throwable cause = assertThrows(Throwable.class, () -> this.capsuleRepository.save(model));

        //check that exception is or is caused by ConstraintViolationException
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }

        assertEquals(ConstraintViolationException.class, cause.getClass());
        assertNotNull(cause.getMessage());
    }

    @Test
    void testJpaSaveAndFindById() {
        assertTrue(postgresContainer.isRunning());

        // test that jpa is up and running (expect no exceptions)
        this.capsuleRepository.count();

        KeyCapsuleDb model = new KeyCapsuleDb();
        model.setCapsuleType(KeyCapsuleDb.CapsuleType.SECP384R1);

        model.setRecipient("123".getBytes());
        model.setPayload("345".getBytes());
        KeyCapsuleDb saved = this.capsuleRepository.save(model);

        assertNotNull(saved);
        assertNotNull(saved.getTransactionId());
        log.debug("Created {}", saved.getTransactionId());

        Optional<KeyCapsuleDb> retrievedOpt = this.capsuleRepository.findById(saved.getTransactionId());
        assertTrue(retrievedOpt.isPresent());

        var dbRecord = retrievedOpt.get();
        assertNotNull(dbRecord.getTransactionId()); // transactionId was generated
        assertTrue(dbRecord.getTransactionId().startsWith("KC"));
        assertNotNull(dbRecord.getCreatedAt()); // createdAt field was filled
        assertEquals(dbRecord.getCapsuleType(), model.getCapsuleType());
        log.debug("Retrieved {}", dbRecord);
    }

    /**
     * Saves the capsule in the database
     * @param dto the capsule dto
     * @return the saved capsule
     */
    protected KeyCapsuleDb saveCapsule(Capsule dto) {
        return this.capsuleRepository.save(
            new KeyCapsuleDb()
                .setCapsuleType(
                    dto.getCapsuleType() == Capsule.CapsuleTypeEnum.ECC_SECP384R1
                        ? KeyCapsuleDb.CapsuleType.SECP384R1
                        : KeyCapsuleDb.CapsuleType.RSA
                )
                .setRecipient(dto.getRecipientId())
                .setPayload(dto.getEphemeralKeyMaterial())
        );
    }

    @SneakyThrows
    protected String capsuleApiUrl() {
        return this.baseUrl + API_CONTEXT_PATH;
    }
}
