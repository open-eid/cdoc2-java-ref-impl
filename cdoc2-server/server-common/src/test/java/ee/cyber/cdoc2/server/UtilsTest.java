package ee.cyber.cdoc2.server;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class UtilsTest {

    @Test
    void getPathAndQueryPart() throws URISyntaxException {
        String fullURI = "https://localhost:44063/key-capsules/KC8f0659982eb50829662a9ee5d4ae87a0";

        assertEquals(new URI("/key-capsules/KC8f0659982eb50829662a9ee5d4ae87a0"),
                Utils.getPathAndQueryPart(new URI(fullURI))
        );
    }
}
