package ee.cyber.cdoc20;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import ee.cyber.cdoc20.util.PasswordUtil;

import static org.junit.jupiter.api.Assertions.assertThrows;


class PasswordValidationTest {

    @Test
    void testStrongPassword() {
        PasswordUtil.validatePassword("StrongPassword".toCharArray());
    }

    @Test
    void shouldAllowSpecialCharacter() {
        PasswordUtil.validatePassword("Password_with_special_characters!".toCharArray());
    }

    @Test
    void shouldAllowNumber() {
        PasswordUtil.validatePassword("PasswordWithNumbers123".toCharArray());
    }

    @Test
    void shouldAllowWhitespace() {
        PasswordUtil.validatePassword("Password With whitespaces".toCharArray());
    }

    @Test
    void shouldFailPwValidationWithoutUpperCaseCharacter() {
        assertThrowsIllegalArgumentException(() ->
                PasswordUtil.validatePassword("password_without_upper_case".toCharArray())
            );
    }

    @Test
    void shouldFailPwValidationWithoutLowerCaseCharacter() {
        assertThrowsIllegalArgumentException(() ->
            PasswordUtil.validatePassword("PASSWORD_WITHOUT_LOWER_CASE".toCharArray())
        );
    }

    @Test
    void shouldFailTooShortPwValidation() {
        assertThrowsIllegalArgumentException(() ->
            PasswordUtil.validatePassword("short".toCharArray())
        );
    }

    @Test
    void shouldFailTooLongPwValidation() {
        String password = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!VeryLongPasswordIsNotAllowed"
            + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        assertThrowsIllegalArgumentException(() ->
            PasswordUtil.validatePassword(password.toCharArray())
        );
    }

    private void assertThrowsIllegalArgumentException(Executable validation) {
        assertThrows(IllegalArgumentException.class, validation);
    }

}
