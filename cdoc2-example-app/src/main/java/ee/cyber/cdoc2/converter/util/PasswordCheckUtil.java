package ee.cyber.cdoc2.converter.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;

import java.util.stream.Collectors;


import static java.time.temporal.ChronoUnit.SECONDS;

public final class PasswordCheckUtil {

    public static final int PW_MIN_LEN = 8;
    public static final int PW_MAX_LEN = 64;
    public static final String PW_LEN_ERR_STR = "Password length must be between "
        + PW_MIN_LEN + " and " + PW_MAX_LEN;
    public static final String PASSWORD_IS_ALREADY_COMPROMISED = "Password is already compromised";

    private PasswordCheckUtil() {}

    private static final Logger log = LoggerFactory.getLogger(PasswordCheckUtil.class);

    private static final String PWNED_RANGE_URI = "https://api.pwnedpasswords.com/range/";

    private static final Duration TIMEOUT = Duration.of(3, SECONDS);

    private static final String USER_AGENT = "cdoc-converter";

    public static boolean isValidLength(char[] passwd) {
        //https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls
        return passwd.length >= PW_MIN_LEN && passwd.length <= PW_MAX_LEN;
    }


    /**
     * Checks password against api.pwnedpasswords.com service, if it has already been compromised
     * @param passwd passwd to check
     * @return if password has been known to be compromised
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws IOException
     * @throws InterruptedException
     */
    public static boolean isPwned(char[] passwd) throws NoSuchAlgorithmException, URISyntaxException, IOException, InterruptedException {

        byte[] bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(passwd)).array();

        @SuppressWarnings("java:S4790")
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(bytes);
        String digest = HexFormat.of().formatHex(sha1.digest()).toUpperCase();

        String dRange = digest.substring(0, 5);
        String partialDigest = digest.substring(5);

        String query = PWNED_RANGE_URI+dRange;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI(query))
            .header("user-agent", USER_AGENT)
            .timeout(TIMEOUT)
            .GET()
            .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
            .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {

            // https://haveibeenpwned.com/API/v3#PwnedPasswords
            try {
                Map<String, Integer> m = response.body().lines().collect(
                    Collectors.toMap(
                        s -> s.split(":")[0],
                        s -> Integer.valueOf(s.split(":")[1])
                    )
                );

                if (m.containsKey(partialDigest)) {
                    log.debug("{} has been compromised {}", digest, m.get(partialDigest));
                }
                return m.containsKey(partialDigest);
            } catch (Exception ex) {
                log.debug("Invalid response: {}", response.body() );
                throw new IOException(ex);
            }
        } else {
            throw new IOException("http query " + query + " failed with " + response.statusCode());
        }
    }
}
