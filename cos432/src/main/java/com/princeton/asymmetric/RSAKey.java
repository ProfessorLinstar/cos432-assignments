package com.princeton.asymmetric;

import com.princeton.random.*;

import java.math.BigInteger;
import java.util.Arrays;

/***
 * This class represents a single RSA key that can perform the RSA encryption
 * and signing algorithms discussed in
 * class. Note that some of the public methods would normally not be part of a
 * production API, but we leave them
 * public for the sake of grading.
 */
public class RSAKey {
    private static final int PADDING_SIZE_BYTES = 16;
    private static final int NONCE_SIZE_BYTES = 16; // must be less than 32 (using SHA-256 hash)

    private BigInteger exponent;
    private BigInteger modulus;

    private int rsaInputSizeBytes; // size of input to RSA encryption (i.e. output of OAEP encoding) in bytes
    private int messageSizeBytes; // size of plaintext message (with basic padding)
    private int nonRandomSizeBytes; // size of messagse + integrity padding

    /***
     * Constructor. Create an RSA key with the given exponent and modulus.
     * 
     * @param theExponent exponent to use for this key's RSA math
     * @param theModulus  modulus to use for this key's RSA math
     */
    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;

        rsaInputSizeBytes = (modulus.bitLength() - 1) / Byte.SIZE;
        messageSizeBytes = rsaInputSizeBytes - PADDING_SIZE_BYTES - NONCE_SIZE_BYTES;
        nonRandomSizeBytes = rsaInputSizeBytes - NONCE_SIZE_BYTES;
    }

    /***
     * Get the exponent used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's exponent
     */
    public BigInteger getExponent() {
        return exponent;
    }

    /***
     * Get the modulus used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /***
     * Pad plaintext input if it is too short for OAEP. Do not call this from
     * {@link #encodeOaep(byte[], PRGen)}.
     *
     * In a "real world" application, this would be a private helper function, but
     * for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * 
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * 
     * <pre>{@code
     * byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     * byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to pad
     * @return padded plaintext of appropriate length for OAEP
     */
    public byte[] addPadding(byte[] input) {
        // IMPLEMENT THIS
        assert input.length < messageSizeBytes;

        byte[] padded = fit(input, messageSizeBytes);
        padded[input.length] = 1;

        return padded;
    }

    /***
     * Remove padding applied by {@link #addPadding(byte[])} method. Do not call
     * this from {@link #decodeOaep(byte[])}.
     *
     * In a "real world" application, this would be a private helper function, but
     * for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * 
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * 
     * <pre>{@code
     * byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     * byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input padded plaintext from which we extract plaintext
     * @return plaintext in {@code input} without padding
     */
    public byte[] removePadding(byte[] input) {
        // IMPLEMENT THIS
        int length;
        for (length = input.length - 1; length >= 0; length--) {
            if (input[length] == 1)
                break;
        }

        return fit(input, length);
    }

    /***
     * Encode a plaintext input with OAEP method. May require basic padding before
     * calling. Do not call
     * {@link #addPadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but
     * for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * 
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * 
     * <pre>{@code
     * byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     * byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to encode
     * @param prgen pseudo-random generator to use in encoding algorithm
     * @return OAEP encoded plaintext
     */
    public byte[] encodeOaep(byte[] input, PRGen prgen) {
        // IMPLEMENT THIS
        assert input.length == messageSizeBytes;

        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        byte[] encoded = fit(input, rsaInputSizeBytes);
        byte[] cipher = new byte[nonRandomSizeBytes];

        // generate nonce and insert at end of encoding
        prgen.nextBytes(nonce);
        System.arraycopy(nonce, 0, encoded, nonRandomSizeBytes, NONCE_SIZE_BYTES);

        // generate prg cipher for message + hash cipher for nonce
        new PRGen(fit(nonce, PRGen.KEY_SIZE_BYTES)).nextBytes(cipher);
        cipher = HashFunction.computeHash(xor(encoded, cipher, 0, nonRandomSizeBytes));
        xor(encoded, cipher, nonRandomSizeBytes, NONCE_SIZE_BYTES);

        return encoded;
    }

    /***
     * Performs bitwise xor operation on input starting at given xOffset, using
     * cipher. Returns an array of length numBytes which is a slice of the
     * portion of the input array which was xor'ed (that is, the slice of size
     * numBytes starting at xOffset).
     *
     * @param input    array to perform xor operation on
     * @param cipher   array to perform xor operation with
     * @param xOffset  where to start in the input array
     * @param numBytes number of bytes to xor
     * @return result of xor operation
     */
    private static byte[] xor(byte[] input, byte[] cipher, int xOffset, int numBytes) {
        byte[] result = new byte[numBytes];
        for (int i = 0; i < numBytes; i++)
            result[i] = input[xOffset + i] ^= cipher[i];
        return result;
    }

    /***
     * Trims or pads the input byte array with zeros to have length numBytes.
     * If input is too long, truncates the right end. If input is too short,
     * pads the right end with zeros.
     *
     * @param input    byte array to be padded or trimmed
     * @param numBytes length of the fitted array
     * @return trimmed/padded array of length numBytes
     */
    private static byte[] fit(byte[] input, int numBytes) {
        byte[] fitted = new byte[numBytes];
        for (int i = 0; i < fitted.length && i < input.length; i++)
            fitted[i] = input[i];
        return fitted;
    }

    /***
     * Decode an OAEP encoded message back into its plaintext representation. May
     * require padding removal after calling.
     * Do not call {@link #removePadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but
     * for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * 
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * 
     * <pre>{@code
     * byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     * byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input OEAP encoded message
     * @return decoded plaintext message
     */
    public byte[] decodeOaep(byte[] input) {
        // IMPLEMENT THIS
        assert input.length == rsaInputSizeBytes;

        // Recover nonce using hash cipher
        byte[] cipher = HashFunction.computeHash(fit(input, nonRandomSizeBytes));
        byte[] nonce = xor(input, cipher, nonRandomSizeBytes, NONCE_SIZE_BYTES);

        // Recover original input using prg stream cipher
        cipher = new byte[nonRandomSizeBytes];
        new PRGen(fit(nonce, PRGen.KEY_SIZE_BYTES)).nextBytes(cipher);
        xor(input, cipher, 0, nonRandomSizeBytes);

        // Verify integrity with zero padding check
        for (int i = messageSizeBytes; i < nonRandomSizeBytes; i++) {
            if (input[i] != 0)
                return null;
        }

        return fit(input, messageSizeBytes);
    }

    /***
     * Get the largest N such that any plaintext of size N bytes can be encrypted
     * with this key and padding/encoding.
     *
     * @return upper bound of plaintext length applicable for this key
     */
    public int maxPlaintextLength() {
        // IMPLEMENT THIS
        return messageSizeBytes - 1;
    }

    /***
     * Encrypt the given plaintext message using RSA algorithm with this key.
     *
     * @param plaintext message to encrypt
     * @param prgen     pseudorandom generator to be used for encoding/encryption
     * @return ciphertext result of RSA encryption on this plaintext/key
     */
    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null)
            throw new NullPointerException();

        // IMPLEMENT THIS
        byte[] padded = addPadding(plaintext);
        byte[] oaepEncoded = encodeOaep(padded, prgen);
        BigInteger encryptedBigInt = HW2Util.bytesToBigInteger(oaepEncoded).modPow(exponent, modulus);
        return encryptedBigInt.toByteArray();
    }

    /***
     * Decrypt the given ciphertext message using RSA algorithm with this key.
     * Effectively the inverse of our
     * {@link #encrypt(byte[], PRGen)} method.
     *
     * @param ciphertext encrypted message to decrypt
     * @return plaintext message
     */
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null)
            throw new NullPointerException();

        // IMPLEMENT THIS
        BigInteger decryptedBigInt = HW2Util.bytesToBigInteger(ciphertext).modPow(exponent, modulus);
        if ((decryptedBigInt.bitLength() - 1) / 8 > rsaInputSizeBytes)
            return null;
        byte[] decrypted = HW2Util.bigIntegerToBytes(decryptedBigInt, rsaInputSizeBytes);
        byte[] decodedPadded = decodeOaep(decrypted);
        return decodedPadded != null ? removePadding(decodedPadded) : null;
    }

    /***
     * Create a digital signature on {@code message}. The signature need not contain
     * the contents of {@code message}; we
     * will assume that a party who wants to verify the signature will already know
     * with which message this signature is
     * meant to be associated.
     *
     * @param message message to sign
     * @param prgen   pseudorandom generator used for signing
     * @return RSA signature of the message using this key
     */
    public byte[] sign(byte[] message, PRGen prgen) {
        if (message == null)
            throw new NullPointerException();

        // IMPLEMENT THIS
        return encrypt(HashFunction.computeHash(message), prgen);
    }

    /***
     * Verify a digital signature against this key. Returns true if and only if
     * {@code signature} is a valid RSA
     * signature on {@code message}; returns false otherwise. A "valid" RSA
     * signature is one that was created by calling
     * {@link #sign(byte[], PRGen)} with the same message on the other RSAKey that
     * belongs to the same RSAKeyPair as
     * this RSAKey object.
     *
     * @param message   message that has been signed
     * @param signature signature to validate against this key
     * @return true iff this RSAKey object's counterpart in a keypair signed the
     *         given message and produced the given
     *         signature
     */
    public boolean verifySignature(byte[] message, byte[] signature) {
        if ((message == null) || (signature == null))
            throw new NullPointerException();

        // IMPLEMENT THIS
        byte[] decrypted = decrypt(signature);
        if (decrypted == null)
            return false;
        return Arrays.equals(decrypted, HashFunction.computeHash(message));
    }

    public static void main(String[] args) {
        PRGen rand = new PRGen(new byte[PRGen.KEY_SIZE_BYTES]);
        RSAKeyPair rsaKP = new RSAKeyPair(rand, 512);

        RSAKey publicKey = rsaKP.getPublicKey();
        RSAKey privateKey = rsaKP.getPrivateKey();

        System.out.println("publicKey.rsaInputSizeBytes: " + publicKey.rsaInputSizeBytes);
        System.out.println("publicKey.messageSizeBytes: " + publicKey.messageSizeBytes);
        System.out.println("publicKey.nonRandomSizeBytes: " + publicKey.nonRandomSizeBytes);

        byte[] message = new byte[] { 0x00, 0x00 };
        System.out.println("Message array: " + Arrays.toString(message));

        byte[] padded = publicKey.addPadding(message);
        System.out.println("Padded array: " + Arrays.toString(padded));
        System.out.println("Padded length: " + padded.length);

        byte[] unpadded = publicKey.removePadding(padded);
        System.out.println("Unpadded array: " + Arrays.toString(unpadded));

        byte[] encoded = publicKey.encodeOaep(padded, rand);
        System.out.println("Encoded array: " + Arrays.toString(encoded));

        byte[] decoded = publicKey.decodeOaep(encoded);
        System.out.println("Decoded array: " + Arrays.toString(decoded));

        System.out.println("\nTesting encryption/decryption:");
        System.out.println("rsaKP.getPrimes()[0]: " + rsaKP.getPrimes()[0]);
        System.out.println("rsaKP.getPrimes()[1]: " + rsaKP.getPrimes()[1]);
        System.out.println("publicKey.exponent:   " + publicKey.exponent);
        System.out.println("privateKey.exponent:  " + privateKey.exponent);
        System.out.println("publicKey.modulus:    " + publicKey.modulus);
        System.out.println("privateKey.modulus:   " + privateKey.modulus);

        byte[] encrypted = publicKey.encrypt(message, rand);
        System.out.println("Encrypted: " + Arrays.toString(encrypted));

        byte[] decrypted = privateKey.decrypt(encrypted);
        System.out.println("Decrypted: " + Arrays.toString(decrypted));

        // byte[] x = new byte[] { 12, 34, 56 };
        // byte[] cipher = new byte[] { 5, 43, 12 };
        // System.out.println("\n*** xor testing ***");
        // System.out.println("original: " + Arrays.toString(x));
        // System.out.println("single xor: " + Arrays.toString(xor(x, cipher, 0, 3)));
        // System.out.println("second xor: " + Arrays.toString(xor(x, cipher, 0, 3)));

        System.out.println("\n*** signature testing ***");
        byte[] signature = privateKey.sign(message, rand);
        System.out.println("signature: " + Arrays.toString(signature));
        System.out.println("signature verified? " +
                publicKey.verifySignature(message, signature));

        signature[0] += 1;
        System.out.println("modified signature: " + Arrays.toString(signature));
        System.out.println("signature verified? " +
                publicKey.verifySignature(message, signature));

        byte[] message2 = new byte[] { 1, 2, 3, 4, 5 };
        signature = privateKey.sign(message2, rand);
        System.out.println("signature on message2:" + Arrays.toString(signature));
        System.out.println("signature verified? " +
                publicKey.verifySignature(message, signature));

        System.out.println("biginteger.tobytearray(-1): " + Arrays.toString(BigInteger.valueOf(-1).toByteArray()));
        System.out.println("biginteger.tobytearray(1): " + Arrays.toString(BigInteger.valueOf(1).toByteArray()));
    }

}
