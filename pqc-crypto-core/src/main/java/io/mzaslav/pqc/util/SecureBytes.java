package io.mzaslav.pqc.util;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Utility class for secure byte array operations.
 * <p>
 * Provides methods for:
 * <ul>
 *   <li>Secure random byte generation</li>
 *   <li>Constant-time byte array comparison</li>
 *   <li>Secure memory wiping</li>
 *   <li>Byte array concatenation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Security Note:</b> All comparison operations use constant-time algorithms
 * to prevent timing attacks.
 * </p>
 *
 * @author mzaslav
 * @since 1.0
 */
public final class SecureBytes {
    
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    private SecureBytes() {
        throw new AssertionError("Utility class - do not instantiate");
    }
    
    /**
     * Generates cryptographically secure random bytes.
     *
     * @param length the number of bytes to generate
     * @return a new byte array filled with random bytes
     * @throws IllegalArgumentException if length is negative
     */
    public static byte[] randomBytes(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("Length cannot be negative: " + length);
        }
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Performs constant-time comparison of two byte arrays.
     * <p>
     * This method is immune to timing attacks as it always compares
     * all bytes regardless of where differences occur.
     * </p>
     *
     * @param a first byte array
     * @param b second byte array
     * @return true if arrays are equal, false otherwise
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    /**
     * Securely wipes a byte array by overwriting it with zeros.
     * <p>
     * Use this method to clear sensitive data (keys, secrets) from memory
     * when they are no longer needed.
     * </p>
     *
     * @param data the byte array to wipe (may be null)
     */
    public static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
    
    /**
     * Securely wipes multiple byte arrays.
     *
     * @param arrays the byte arrays to wipe
     */
    public static void wipeAll(byte[]... arrays) {
        if (arrays != null) {
            for (byte[] array : arrays) {
                wipe(array);
            }
        }
    }
    
    /**
     * Concatenates multiple byte arrays into a single array.
     *
     * @param arrays the arrays to concatenate
     * @return a new byte array containing all input arrays concatenated
     */
    public static byte[] concat(byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            return new byte[0];
        }
        
        int totalLength = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                totalLength += array.length;
            }
        }
        
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                System.arraycopy(array, 0, result, offset, array.length);
                offset += array.length;
            }
        }
        return result;
    }
    
    /**
     * Creates a copy of a byte array.
     *
     * @param data the array to copy
     * @return a new byte array with the same contents, or null if input is null
     */
    public static byte[] copy(byte[] data) {
        if (data == null) {
            return null;
        }
        return Arrays.copyOf(data, data.length);
    }
    
    /**
     * Extracts a portion of a byte array.
     *
     * @param data   the source array
     * @param offset the starting position
     * @param length the number of bytes to extract
     * @return a new byte array containing the specified portion
     * @throws IllegalArgumentException if parameters are invalid
     */
    public static byte[] slice(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IllegalArgumentException(
                String.format("Invalid slice: offset=%d, length=%d, array.length=%d",
                    offset, length, data.length));
        }
        return Arrays.copyOfRange(data, offset, offset + length);
    }
}
