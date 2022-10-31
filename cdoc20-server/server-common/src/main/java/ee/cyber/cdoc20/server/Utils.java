package ee.cyber.cdoc20.server;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.modelmapper.AbstractConverter;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;

/**
 * Server utilities.
 */
public final class Utils {

    /**
     * ModelMapper to convert between dto and jpa models
     */
    public static final ModelMapper MODEL_MAPPER = getModelMapper();

    private Utils() {
    }

    /**
     * Fix OpenApi generator broken base url. Return only Path and Query part of the URI
     */
    public static URI fixOABrokenBaseURL(URI u) throws URISyntaxException {
        List<String> patterns = List.of(
                // "\\$\\{(.*?)\\}",
                "\\$%7B(.*?)%7D"); //same, but urlencoded

        String uriStr = u.toString();
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

        // return only path and query part of URI as host and port might be different, when running behind load balancer
        URI uri = new URI(uriStr).normalize();

        if (uri.getQuery() != null) {
            return new URI(uri.getPath() + '?' + uri.getQuery());
        } else {
            return new URI(uri.getPath());
        }
    }

    private static ModelMapper getModelMapper() {
        var mapper = new ModelMapper();
        Converter<byte[], String> byteArrayToBase64Converter = new AbstractConverter<>() {
            @Override
            protected String convert(byte[] bytes) {
                return Base64.getEncoder().encodeToString(bytes);
            }
        };

        Converter<String, byte[]> base64ToByteArrayConverter = new AbstractConverter<>() {
            @Override
            protected byte[] convert(String base64) {
                return Base64.getDecoder().decode(base64);
            }
        };
        mapper.addConverter(byteArrayToBase64Converter);
        mapper.addConverter(base64ToByteArrayConverter);
        return mapper;
    }
}
