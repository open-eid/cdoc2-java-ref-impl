package ee.cyber.cdoc20.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Server utilities.
 */
public final class Utils {

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    private Utils() {
    }

    /**
     * Fix OpenApi generator broken base url. Return only Path and Query part of the URI
     * @see <a href="https://github.com/OpenAPITools/openapi-generator/issues/13552">Openapi-generator bug-13552</a>
     */
    public static URI fixOABrokenBaseURL(URI u) throws URISyntaxException {
        List<String> patterns = List.of(
                // "\\$\\{(.*?)\\}",
                "\\$%7B(.*?)%7D"); //same, but urlencoded

        String uriStr = u.toString();

        log.debug("URI u {}", uriStr);
        // OpenAPI generated base url are broken as
        // http://localhost/${openapi.openAPIDefinition.base-path:/v0}/flexiblity-needs
        // http://localhost/${openapi.flexibilityResource.base-path:}/flexibility-resources
        // Second colon (:) is removed by some Spring code, so that
        // url ends up  http://localhost/${openapi.openAPIDefinition.base-path/v0}/flexiblity-needs
        // fix that

        for (String pattern: patterns) {
            String basePath = ".";
            final Matcher m = Pattern.compile(pattern).matcher(uriStr);
            if (m.find()) {
                String gibberish = uriStr.substring(m.start(), m.end());

                String[] split = gibberish.split("/");
                if (split.length > 1) {
                    basePath = split[split.length - 1];
                    if (basePath.endsWith("%7D")) {
                        basePath = basePath.substring(0, basePath.indexOf("%7D"));
                    }
                }

                uriStr = uriStr.replaceAll(pattern, basePath);
            }

        }

        log.debug("result {}", uriStr);

        // return only path and query part of URI as host and port might be different, when running behind load balancer
        URI fullUri = new URI(uriStr).normalize();
        return getPathAndQueryPart(fullUri);
    }

    public static URI getPathAndQueryPart(URI fullURI) throws URISyntaxException {
        // return only path and query part of URI as host and port might be different, when running behind load balancer

        String uriStr = fullURI.toString();
        URI uri = new URI(uriStr).normalize();

        if (uri.getQuery() != null) {
            return new URI(uri.getPath() + '?' + uri.getQuery());
        } else {
            return new URI(uri.getPath());
        }
    }
}
