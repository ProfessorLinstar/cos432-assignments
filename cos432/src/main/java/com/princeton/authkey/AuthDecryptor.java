package com.princeton.authkey;

import com.princeton.random.*;
import java.util.Arrays;

/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/
public class AuthDecryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;
    public static final int MAC_SIZE_BYTES = AuthEncryptor.MAC_SIZE_BYTES;

    private PRF prf;

    // Instance variables.
    // IMPLEMENT THIS

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS
        prf = new PRF(key);
    }

    // Decrypts and authenticates the contents of <in>. <in> should have been
    // encrypted using your implementation of AuthEncryptor. The nonce has been
    // included in <in>. If the integrity of <in> cannot be verified, then
    // returns null. Otherwise, returns a newly allocated byte[] containing the
    // plaintext value that was originally encrypted.
    public byte[] authDecrypt(byte[] in) {
        // IMPLEMENT THIS
        byte[] decKey = prf.eval(in, in.length - NONCE_SIZE_BYTES, NONCE_SIZE_BYTES);
        byte[] decrypted = new byte[in.length - MAC_SIZE_BYTES - NONCE_SIZE_BYTES];
        StreamCipher cipher = new StreamCipher(decKey, in, in.length - NONCE_SIZE_BYTES);

        // System.out.println("Got this decKey : " + Arrays.toString(decKey));

        return authDecrypt(in, decrypted, cipher);
    }

    // Decrypts and authenticates the contents of <in>. <in> should have been
    // encrypted using your implementation of AuthEncryptor. The nonce used to
    // encrypt the data is provided in <nonce>. If the integrity of <in> cannot
    // be verified, then returns null. Otherwise, returns a newly allocated
    // byte[] containing the plaintext value that was originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;

        // IMPLEMENT THIS
        byte[] decKey = prf.eval(nonce);
        byte[] decrypted = new byte[in.length - MAC_SIZE_BYTES];
        StreamCipher cipher = new StreamCipher(decKey, nonce);

        // System.out.println("Got this decKey : " + Arrays.toString(decKey));

        return authDecrypt(in, decrypted, cipher);
    }

    // Decrypts and authenticates the contents of <in>. <in> should have been
    // encrypted using your implementation of AuthEncryptor, with key <decKey>
    // and cipher <cipher>. If the integrity of <in> cannot be verified, then
    // returns null. Otherwise, returns a newly allocated byte[] containing the
    // plaintext value that was originally encrypted.
    private byte[] authDecrypt(byte[] in, byte[] decrypted, StreamCipher cipher) {

        // System.out.println("decrypted pre decryption: " +
        // Arrays.toString(decrypted));
        cipher.cryptBytes(in, 0, decrypted, 0, decrypted.length);
        // System.out.println("decrypted post decryption: " +
        // Arrays.toString(decrypted));

        byte[] mac = prf.eval(in, 0, decrypted.length);
        // System.out.println("found this mac: " + Arrays.toString(mac));
        for (int i = 0; i < mac.length; i++) {
            if (mac[i] != in[decrypted.length + i])
                return null;
        }

        return decrypted;
    }

    public static void main(String[] args) {
        PRGen prg = new PRGen(new byte[PRGen.KEY_SIZE_BYTES]);
        int maxLength = 20;

        for (int i = 0; i < 1000; i++) {
            int length = prg.nextInt(0, maxLength);

            byte[] message = new byte[length];
            byte[] key = new byte[StreamCipher.KEY_SIZE_BYTES];
            byte[] nonce = new byte[StreamCipher.NONCE_SIZE_BYTES];

            prg.nextBytes(message);
            prg.nextBytes(key);
            prg.nextBytes(nonce);

            AuthEncryptor encryptor = new AuthEncryptor(key);
            AuthDecryptor decryptor = new AuthDecryptor(key);

            System.out.println("message                 : " + Arrays.toString(message));
            System.out.println("key                     : " + Arrays.toString(key));
            System.out.println("nonce                   : " + Arrays.toString(nonce));

            System.out.println();

            byte[] encrypted = encryptor.authEncrypt(message, nonce, true);
            System.out.println("encrypted               : " + Arrays.toString(encrypted));
            byte[] decrypted = decryptor.authDecrypt(encrypted);
            System.out.println("decrypted               : " + Arrays.toString(decrypted));
            assert Arrays.equals(message, decrypted);

            System.out.println();

            encrypted = encryptor.authEncrypt(message, nonce, false);
            System.out.println("encrypted without nonce : " + Arrays.toString(encrypted));
            decrypted = decryptor.authDecrypt(encrypted, nonce);
            System.out.println("decrypted without nonce : " + Arrays.toString(decrypted));
            assert Arrays.equals(message, decrypted);

        }

    }
}
