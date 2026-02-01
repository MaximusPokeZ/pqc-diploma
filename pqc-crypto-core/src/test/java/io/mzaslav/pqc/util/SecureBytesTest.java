package io.mzaslav.pqc.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link SecureBytes} utility class.
 */
@DisplayName("SecureBytes")
class SecureBytesTest {

    @Nested
    @DisplayName("randomBytes")
    class RandomBytesTest {

        @Test
        @DisplayName("should generate bytes of requested length")
        void shouldGenerateCorrectLength() {
            byte[] bytes = SecureBytes.randomBytes(32);
            assertThat(bytes).hasSize(32);
        }

        @Test
        @DisplayName("should generate unique bytes each call")
        void shouldGenerateUniqueBytes() {
            byte[] bytes1 = SecureBytes.randomBytes(32);
            byte[] bytes2 = SecureBytes.randomBytes(32);
            assertThat(bytes1).isNotEqualTo(bytes2);
        }

        @Test
        @DisplayName("should generate empty array for length 0")
        void shouldGenerateEmptyForZeroLength() {
            byte[] bytes = SecureBytes.randomBytes(0);
            assertThat(bytes).isEmpty();
        }

        @Test
        @DisplayName("should throw for negative length")
        void shouldThrowForNegativeLength() {
            assertThatThrownBy(() -> SecureBytes.randomBytes(-1))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("constantTimeEquals")
    class ConstantTimeEqualsTest {

        @Test
        @DisplayName("should return true for equal arrays")
        void shouldReturnTrueForEqualArrays() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {1, 2, 3, 4, 5};
            assertThat(SecureBytes.constantTimeEquals(a, b)).isTrue();
        }

        @Test
        @DisplayName("should return false for different arrays")
        void shouldReturnFalseForDifferentArrays() {
            byte[] a = {1, 2, 3, 4, 5};
            byte[] b = {1, 2, 3, 4, 6};
            assertThat(SecureBytes.constantTimeEquals(a, b)).isFalse();
        }

        @Test
        @DisplayName("should return false for different lengths")
        void shouldReturnFalseForDifferentLengths() {
            byte[] a = {1, 2, 3};
            byte[] b = {1, 2, 3, 4};
            assertThat(SecureBytes.constantTimeEquals(a, b)).isFalse();
        }

        @Test
        @DisplayName("should handle null arrays")
        void shouldHandleNullArrays() {
            assertThat(SecureBytes.constantTimeEquals(null, null)).isTrue();
            assertThat(SecureBytes.constantTimeEquals(new byte[0], null)).isFalse();
            assertThat(SecureBytes.constantTimeEquals(null, new byte[0])).isFalse();
        }
    }

    @Nested
    @DisplayName("wipe")
    class WipeTest {

        @Test
        @DisplayName("should zero out array")
        void shouldZeroOutArray() {
            byte[] data = {1, 2, 3, 4, 5};
            SecureBytes.wipe(data);
            assertThat(data).containsOnly((byte) 0);
        }

        @Test
        @DisplayName("should handle null array")
        void shouldHandleNullArray() {
            assertThatCode(() -> SecureBytes.wipe(null)).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("concat")
    class ConcatTest {

        @Test
        @DisplayName("should concatenate arrays")
        void shouldConcatenateArrays() {
            byte[] a = {1, 2};
            byte[] b = {3, 4};
            byte[] c = {5};
            
            byte[] result = SecureBytes.concat(a, b, c);
            assertThat(result).containsExactly(1, 2, 3, 4, 5);
        }

        @Test
        @DisplayName("should handle null arrays in concat")
        void shouldHandleNullInConcat() {
            byte[] a = {1, 2};
            byte[] result = SecureBytes.concat(a, null, new byte[]{3});
            assertThat(result).containsExactly(1, 2, 3);
        }

        @Test
        @DisplayName("should return empty for no arguments")
        void shouldReturnEmptyForNoArgs() {
            assertThat(SecureBytes.concat()).isEmpty();
        }
    }

    @Nested
    @DisplayName("copy")
    class CopyTest {

        @Test
        @DisplayName("should create independent copy")
        void shouldCreateIndependentCopy() {
            byte[] original = {1, 2, 3};
            byte[] copy = SecureBytes.copy(original);
            
            assertThat(copy).isEqualTo(original);
            assertThat(copy).isNotSameAs(original);
            
            // Modify original, copy should be unchanged
            original[0] = 99;
            assertThat(copy[0]).isEqualTo((byte) 1);
        }

        @Test
        @DisplayName("should return null for null input")
        void shouldReturnNullForNullInput() {
            assertThat(SecureBytes.copy(null)).isNull();
        }
    }

    @Nested
    @DisplayName("slice")
    class SliceTest {

        @Test
        @DisplayName("should extract portion of array")
        void shouldExtractPortion() {
            byte[] data = {1, 2, 3, 4, 5};
            byte[] slice = SecureBytes.slice(data, 1, 3);
            assertThat(slice).containsExactly(2, 3, 4);
        }

        @Test
        @DisplayName("should throw for invalid parameters")
        void shouldThrowForInvalidParams() {
            byte[] data = {1, 2, 3};
            
            assertThatThrownBy(() -> SecureBytes.slice(null, 0, 1))
                .isInstanceOf(IllegalArgumentException.class);
            
            assertThatThrownBy(() -> SecureBytes.slice(data, -1, 1))
                .isInstanceOf(IllegalArgumentException.class);
            
            assertThatThrownBy(() -> SecureBytes.slice(data, 0, 10))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
