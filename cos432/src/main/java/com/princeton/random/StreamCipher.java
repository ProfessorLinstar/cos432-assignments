// package com.princeton.random;

/**********************************************************************************/
/* StreamCipher.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a stream cipher, which encrypts or decrypts */
/*              a stream of bytes (the two operations are identical).             */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement a stream cipher.                                          */
/* ------------------------------------------------------------------------------ */
/* USAGE: Create a new StreamCipher with key k of length <KEY_SIZE_BYTES> and     */
/*        nonce n of length NONCE_SIZE_BYTES:                                     */
/*            StreamCipher enc = new StreamCipher(k, n);                          */
/*                                                                                */
/*        Encrypt two bytes b1 and b2:                                            */
/*            byte e1 = enc.cryptByte(b1);                                        */
/*            byte e2 = enc.cryptByte(b2);                                        */
/*                                                                                */
/*        Decrypt two bytes e1 and e2.  First, create a StreamCipher with the     */
/*        same key and nonce, and then call cryptByte() on the encrypted bytes in */
/*        the same order.                                                         */
/*            StreamCipher dec = new StreamCipher(k, n);                          */
/*            byte d1 = dec.cryptByte(e1);                                        */
/*            byte d2 = dec.cryptByte(e2);                                        */
/*            assert (d1 == b1 && d2 == b2);                                      */
/**********************************************************************************/
public class StreamCipher {
    // Class constants.
    public static final int KEY_SIZE_BYTES = PRGen.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = 8;

    // Instance variables.
    // IMPLEMENT THIS
    private PRGen prg;

    // Creates a new StreamCipher with key <key> and nonce composed of
    // nonceArr[nonceOffset] through nonceArr[nonceOffset + NONCE_SIZE_BYTES - 1].
    public StreamCipher(byte[] key, byte[] nonceArr, int nonceOffset) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS
        // use key and nonce to randomize initial state of prg
        prg = new PRGen((new PRF(key)).eval(nonceArr, nonceOffset, NONCE_SIZE_BYTES));
    }

    public StreamCipher(byte[] key, byte[] nonce) {
        this(key, nonce, 0); // Call the other constructor.
    }

    // Encrypts or decrypts the next byte in the stream.
    public byte cryptByte(byte in) {
        // IMPLEMENT THIS
        return (byte) (in ^ prg.next(8)); // xor symmetric cryption
    }

    // Encrypts or decrypts multiple bytes.
    // Encrypts or decrypts inBuf[inOffset] through inBuf[inOffset + numBytes - 1],
    // storing the result in outBuf[outOffset] through outBuf[outOffset + numBytes -
    // 1].
    public void cryptBytes(byte[] inBuf, int inOffset,
            byte[] outBuf, int outOffset, int numBytes) {
        for (int i = 0; i < numBytes; i++)
            outBuf[outOffset + i] = cryptByte(inBuf[inOffset + i]);

    }

    public static void main(String[] args) {
        byte[] nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 9 };
        StreamCipher enc = new StreamCipher(new byte[KEY_SIZE_BYTES], nonce);
        StreamCipher dec = new StreamCipher(new byte[KEY_SIZE_BYTES], nonce);

        PRGen prg = new PRGen(new byte[KEY_SIZE_BYTES]);
        for (int i = 0; i < 10; i++) {
            int next = prg.next(8);
            byte e = enc.cryptByte((byte) next);
            System.out.println("Encoding: " + Integer.toBinaryString(next));
            System.out.println("Decoding: " + Integer.toBinaryString(dec.cryptByte(e) & 0xff));
            System.out.println("Cryption: " + Integer.toBinaryString(e & 0xff));
            System.out.println();
        }
    }
}
