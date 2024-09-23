package ee.cyber.cdoc2;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Isolated;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import ee.cyber.cdoc2.client.Cdoc2KeyCapsuleApiClient;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.client.model.Capsule;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


@Isolated
@ExtendWith(MockitoExtension.class)
class KeyCapsuleClientTest {

    @InjectMocks
    KeyCapsuleClientImpl capsuleClient;

    @Mock
    Cdoc2KeyCapsuleApiClient capsuleApiClient;

    @Test
    void testCapsuleCreationWithoutRequestedExpiry() throws Exception {
        Capsule capsule = createCapsule();

        capsuleClient.storeCapsule(capsule);

        verify(capsuleApiClient, times(1)).createCapsule(capsule);
    }

    @Test
    void shouldCallCreateCapsuleWithExpiryTimeWhenExpiryDurationIsSet() throws Exception {
        Capsule capsule = createCapsule();

        Duration duration = Duration.ofDays(365);

        capsuleClient.setExpiryDuration(duration);
        capsuleClient.storeCapsule(capsule);

        verify(capsuleApiClient, times(1)).createCapsule(any(), any());
    }

    private Capsule createCapsule() {
        return new Capsule()
            .capsuleType(Capsule.CapsuleTypeEnum.ECC_SECP384R1)
            .recipientId(new byte[1024])
            .ephemeralKeyMaterial(new byte[1024]);
    }

}
