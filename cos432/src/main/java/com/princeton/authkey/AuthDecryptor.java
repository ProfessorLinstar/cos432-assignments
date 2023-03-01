package com.princeton.authkey;

import com.princeton.random.*;

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
        StreamCipher cipher = new StreamCipher(decKey, in, in.length - MAC_SIZE_BYTES - NONCE_SIZE_BYTES);
        return authDecrypt(in, decKey, cipher);
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
        StreamCipher cipher = new StreamCipher(decKey, in, in.length - MAC_SIZE_BYTES);
        return authDecrypt(in, decKey, cipher);
    }

    // Decrypts and authenticates the contents of <in>. <in> should have been
    // encrypted using your implementation of AuthEncryptor, with key <decKey>
    // and cipher <cipher>. If the integrity of <in> cannot be verified, then
    // returns null. Otherwise, returns a newly allocated byte[] containing the
    // plaintext value that was originally encrypted.
    private byte[] authDecrypt(byte[] in, byte[] decKey, StreamCipher cipher) {
        byte[] decrypted = new byte[in.length - MAC_SIZE_BYTES - NONCE_SIZE_BYTES];

        cipher.cryptBytes(in, 0, decrypted, 0, decrypted.length);

        byte[] mac = prf.eval(decrypted);
        for (int i = 0; i < mac.length; i++) {
            if (mac[i] != in[decrypted.length + i])
                return null;
        }

        return decrypted;
    }
}
