package ee.cyber.cdoc20.server;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

/**
 * Display time on info endpoint (/actuator/info)
 */
@Component
public class SystemTimeInfoContributor implements InfoContributor {
    @Override
    public void contribute(Info.Builder builder) {
        Map<String, Object> details = new HashMap<>();
        details.put("system.time", Instant.now().truncatedTo(ChronoUnit.SECONDS));

        builder.withDetails(details);
    }
}
