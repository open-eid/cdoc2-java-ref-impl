package ee.cyber.cdoc2;

import org.junit.jupiter.api.Test;

import static ee.cyber.cdoc2.util.IdCodeValidationUtil.getValidatedIdentityCode;
import static org.junit.jupiter.api.Assertions.assertEquals;


class IdCodeValidationUtilTest {

    @Test
    void testSuccessfulIdCodeValidation() {
        String validatedIdCode = getValidatedIdentityCode("51307149560");
        assertEquals("51307149560", validatedIdCode);

        getValidatedIdentityCode("60001019939");
        getValidatedIdentityCode("60001019983");
        getValidatedIdentityCode("60001019961");
        getValidatedIdentityCode("60001019972");
        getValidatedIdentityCode("50001018908");
        getValidatedIdentityCode("30303039914");
    }

}
