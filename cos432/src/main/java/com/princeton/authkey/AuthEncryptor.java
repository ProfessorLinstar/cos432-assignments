package com.princeton.authkey;

import com.princeton.random.*;
import java.util.Arrays;

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

    private PRF encPrf;
    private PRF macPrf;

    // Instance variables.
    // IMPLEMENT THIS

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS
        key = key.clone();
        PRGen prg = new PRGen(key);

        prg.nextBytes(key);
        encPrf = new PRF(key);
        prg.nextBytes(key);
        macPrf = new PRF(key);
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are
    // protected against those who do not
    // know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the
    // output.
    // Returns a newly allocated byte[] containing the authenticated encryption of
    // the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        // IMPLEMENT THIS
        assert nonce.length == NONCE_SIZE_BYTES;
        byte[] encKey = encPrf.eval(nonce);
        byte[] encrypted = new byte[in.length + MAC_SIZE_BYTES + (includeNonce ? NONCE_SIZE_BYTES : 0)];

        // System.out.println("using this encKey: " + Arrays.toString(encKey));

        StreamCipher cipher = new StreamCipher(encKey, nonce);
        cipher.cryptBytes(in, 0, encrypted, 0, in.length);
        System.out.println("updating macPrf with this nonce: " + Arrays.toString(nonce));
        macPrf.update(nonce);
        System.out.println("encrypted pre-mac: " + Arrays.toString(encrypted));
        macPrf.eval(encrypted, 0, in.length, encrypted, in.length); // MAC generation
        

        byte[] macEnc = new byte[PRF.OUTPUT_SIZE_BYTES];
        System.arraycopy(encrypted, in.length, macEnc, 0, macEnc.length);
        System.out.println("macEnc: " + Arrays.toString(macEnc));
        System.out.println("encrypted post-mac:" + Arrays.toString(encrypted));

        if (includeNonce)
            System.arraycopy(nonce, 0, encrypted, encrypted.length - NONCE_SIZE_BYTES, NONCE_SIZE_BYTES);

        System.out.println("encrypted postnonc:" + Arrays.toString(encrypted));

        return encrypted;
    }
}
