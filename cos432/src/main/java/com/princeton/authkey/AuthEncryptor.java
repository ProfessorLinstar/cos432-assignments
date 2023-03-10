package com.princeton.authkey;

import com.princeton.random.*;

/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;
    public static final int MAC_SIZE_BYTES = PRF.OUTPUT_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS

    private byte[] key;
    private PRF macPrf;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS
        PRGen prg = new PRGen(key);

        this.key = new byte[KEY_SIZE_BYTES];
        prg.nextBytes(this.key);
        macPrf = new PRF(this.key); // generate a MAC PRF using a randomly generated key
        prg.nextBytes(this.key); // choose another random key as the shared encryption key
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity
    // are protected against those who do not know the key and nonce. If
    // <nonceIncluded> is true, then the nonce is included in plaintext with
    // the output. Returns a newly allocated byte[] containing the
    // authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        // IMPLEMENT THIS
        assert nonce.length == NONCE_SIZE_BYTES;
        byte[] encrypted = new byte[in.length + MAC_SIZE_BYTES + (includeNonce ? NONCE_SIZE_BYTES : 0)];
        // encrypted is the concatenation <ciphertext> + <mac> + <nonce>, where <nonce>
        // is included only if includeNonce is true

        new StreamCipher(key, nonce).cryptBytes(in, 0, encrypted, 0, in.length);
        macPrf.update(nonce); // make sure that MAC depends on NONCE
        macPrf.eval(encrypted, 0, in.length, encrypted, in.length); // MAC generation

        if (includeNonce) // copy nonce into end of encyrpted array
            System.arraycopy(nonce, 0, encrypted, encrypted.length - NONCE_SIZE_BYTES, NONCE_SIZE_BYTES);

        return encrypted;
    }
}
