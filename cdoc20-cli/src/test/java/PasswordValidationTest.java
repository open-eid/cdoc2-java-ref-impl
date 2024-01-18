import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import ee.cyber.cdoc20.cli.PasswordValidationUtil;

import static org.junit.jupiter.api.Assertions.assertThrows;


class PasswordValidationTest {

    @Test
    void testStrongPassword() {
        PasswordValidationUtil.validatePassword("StrongPassword".toCharArray());
    }

    @Test
    void shouldFailPwValidationWithoutUpperCaseCharacter() {
        assertThrowsIllegalArgumentException(() ->
                PasswordValidationUtil.validatePassword("password_without_upper_case".toCharArray())
            );
    }

    @Test
    void shouldFailPwValidationWithoutLowerCaseCharacter() {
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword("PASSWORD_WITHOUT_LOWER_CASE".toCharArray())
        );
    }

    @Test
    void shouldFailTooShortPwValidation() {
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword("short".toCharArray())
        );
    }

    @Test
    void shouldFailTooLongPwValidation() {
        String password = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!VeryLongPasswordIsNotAllowed"
            + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        assertThrowsIllegalArgumentException(() ->
            PasswordValidationUtil.validatePassword(password.toCharArray())
        );
    }

    private void assertThrowsIllegalArgumentException(Executable validation) {
        assertThrows(IllegalArgumentException.class, validation);
    }

}
