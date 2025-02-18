package ee.cyber.cdoc2.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Utility class for national ID code validation.
 */
public final class IdCodeValidationUtil {

    private static final String IDENTITY_CODE_PATTERN = "\\d{11}";
    private static final Pattern idPattern = Pattern.compile(IDENTITY_CODE_PATTERN);

    private IdCodeValidationUtil() { }

    /**
     * Validates national identity code.
     * @param idCode identity code
     * @return identity code
     * @throws IllegalArgumentException if identity code validation has failed
     */
    public static String getValidatedIdentityCode(String idCode) {
        Matcher matcher = idPattern.matcher(idCode);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Identity number must be of 11 numbers: " + idCode);
        }

        int checksum = Integer.parseInt(idCode.substring(10));
        String idNumberWithoutChecksum = idCode.substring(0, 10);

        int calculatedChecksum = getCalculatedChecksum(idNumberWithoutChecksum);

        if (checksum != calculatedChecksum) {
            throw new IllegalArgumentException("Invalid identity number: " + idCode);
        }

        return idCode;
    }

    private static int getCalculatedChecksum(String idNumberWithoutChecksum) {
        int[] firstTierMultipliers = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1};
        int calculatedChecksum = calculateChecksum(idNumberWithoutChecksum, firstTierMultipliers);
        if (10 == calculatedChecksum) {
            return getSecondTierCalculatedChecksum(idNumberWithoutChecksum);
        }

        return calculatedChecksum;
    }

    private static int getSecondTierCalculatedChecksum(String idNumberWithoutChecksum) {
        int[] secondTierMultipliers = {3, 4, 5, 6, 7, 8, 9, 1, 2, 3};
        int calculatedChecksum = calculateChecksum(idNumberWithoutChecksum, secondTierMultipliers);
        if (10 == calculatedChecksum) {
            calculatedChecksum = 0;
        }
        return calculatedChecksum;
    }

    private static int calculateChecksum(String idNumberWithoutChecksum, int[] tierMultipliers) {
        int sum = 0;
        for (int i = 0; i < tierMultipliers.length; i++) {
            sum =
                sum + (tierMultipliers[i]
                    * Integer.parseInt(idNumberWithoutChecksum.substring(i, i + 1)));
        }
        return sum % 11;
    }

}
