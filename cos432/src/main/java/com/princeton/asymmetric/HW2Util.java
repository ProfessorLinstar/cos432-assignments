package com.princeton.asymmetric;

import java.math.BigInteger;
import java.util.Arrays;

/***
 * This utility class helps facilitate conversion between BigInteger and byte[].
 *
 * For converting {BigInteger -> byte[] -> BigInteger}, you may use the BigInteger.toByteArray() method and the
 * BigInteger(byte[]) constructor, since the BigInteger library will correctly output a byte array that works with its
 * own constructor. For example, the following code will create an equivalent BigInteger:
 * <pre>{@code
 *  BigInteger bigInt;
 *  // ...
 *  byte[] byteArray = bigInt.toByteArray();
 *  bigInt = new BitInteger(byteArray);
 * }</pre>
 *
 * For converting {byte[] -> BigInteger -> byte[]}, using built-in methods can lead to errors. Instead, you should use
 * the following methods provided in this file:
 * <pre>{@code
 *  byte[] byteArray;
 *  int messageLength;
 *  // ...
 *  BigInteger bigInt = HW2Util.bytesToBigInteger(byteArray);
 *  byteArray = HW2Util.bigIntegerToBytes(bigInt, messageLength);
 *  }</pre>
 * Note that the second argument to bigIntegerToBytes(...) must be the exact length of the resulting byteArray. You
 * should determine this based on constants or save the length based on the initial size.
 */
public class HW2Util {
    /***
     * Convert a byte array into a BigInteger object. This operation is the inverse of the
     * {@link #bigIntegerToBytes(BigInteger, int) bigIntegerToBytes(BigInteger, int) method}.
     *
     * @param buf   The buffer of big-endian bytes (byte array) to convert into a BigInteger object
     * @return BigInteger object with positive value equivalent to the big-endian formatted byte array
     */
    public static BigInteger bytesToBigInteger(byte[] buf) {
        // setting the sign to one (positive) and constructing from big-endian constructor
        return new BigInteger(1, buf);
    }

    /***
     * Convert a non-negative-valued BigInteger object into a big-endian byte array representation. This operation is
     * the inverse of the {@link #bytesToBigInteger(byte[]) bytesToBigInteger method}.
     *
     * @param x BigInteger object whose value will be converted to a byte array x >= 0
     * @param outputSize expected size of the output array, which must be supplied here because the code cannot tell
     *                   what array length should be returned to the caller
     * @return big-endian byte array representation of x returned in array of size outputSize
     */
    public static byte[] bigIntegerToBytes(BigInteger x, int outputSize) {
        if (x.compareTo(BigInteger.ZERO) < 0)
            throw new IllegalArgumentException("bigIntegerToBytes only hanldles non-negative BitInteger objects");
        if (outputSize < 1)
            throw new IllegalArgumentException("BigInteger output array size outputSize must be at least one byte");

        // if the output lengths match, we can just return built-in conversion
        byte[] rawByteArray = x.toByteArray();
        if (rawByteArray.length == outputSize) return rawByteArray;

        byte[] ret = new byte[outputSize];
        if (rawByteArray.length == outputSize + 1) {
            // manually copy the entire raw array without the sign-extended byte
            System.arraycopy(rawByteArray, 1, ret, 0, rawByteArray.length - 1);
        } else if (rawByteArray.length < outputSize) {  // rawByteArray.length < outputSize
            // this handles the case where we want an output that is longer than the built-in function returned
            // here we just pad the big-endian array with zeros in the most significant bytes
            int sizeDiff = outputSize - rawByteArray.length;
            System.arraycopy(rawByteArray, 0, ret, sizeDiff, rawByteArray.length);
        } else {
            throw new IllegalArgumentException("bigIntegerToBytes cannot fit result into requested outputSize " +
                    "(" + rawByteArray.length + " > " + outputSize + ")");
        }
        return ret;
    }

    public static void main(String[] args) {
        byte[] bytes = new byte[]{1, 0};
        BigInteger bigInt = bytesToBigInteger(bytes);

        System.out.println("bytes: " + Arrays.toString(bytes));
        System.out.println("bytesToBigInteger(bytes): " + bigInt);
        System.out.println("bigIntegerToBytes(bytesToBigInteger(bytes), 1): " + Arrays.toString(bigIntegerToBytes(bigInt, 1)));
        System.out.println("bigIntegerToBytes(bytesToBigInteger(bytes), 2): " + Arrays.toString(bigIntegerToBytes(bigInt, 2)));
    }
}
