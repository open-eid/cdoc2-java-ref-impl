package ee.cyber.cdoc20.server;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * On server start-up lists registered endpoints and their handler classes (DEBUG). Example:
 * <pre>
 * {GET [/ecc-details/{transactionId}], produces [application/json]}: ee.cyber.cdoc20.server.api.EccDetailsApiController#getEccDetailsByTransactionId(String)
 * {POST [/ecc-details], consumes [application/json]}: ee.cyber.cdoc20.server.api.EccDetailsApiController#createEccDetails(ServerEccDetails)
 * </pre>
 */
@Component
public class RegisteredEndpointsLogger implements ApplicationListener<ContextRefreshedEvent> {
    private static final Logger log = LoggerFactory.getLogger(RegisteredEndpointsLogger.class);

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        ApplicationContext applicationContext = event.getApplicationContext();
        RequestMappingHandlerMapping requestMappingHandlerMapping = applicationContext
                .getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
        Map<RequestMappingInfo, HandlerMethod> map = requestMappingHandlerMapping
                .getHandlerMethods();
        if (log.isDebugEnabled()) {
            map.forEach((key, value) -> log.debug("{}:{} ", key, value));
        }
    }

}
