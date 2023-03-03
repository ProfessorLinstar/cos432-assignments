package com.princeton.authkey;

import com.princeton.random.*;
import com.princeton.asymmetric.*;

import java.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides
    // authenticated encryption for the messages that pass
    // over the channel. It also guarantees that messages are delivered
    // on the receiving end in the same order they were sent (returning
    // null otherwise). Also, when the channel is first set up,
    // the client authenticates the server's identity, and the necessary
    // steps are taken to detect any man-in-the-middle (and to close the
    // connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    // calls to the underlying InsecureChannel.

    private AuthEncryptor enc;
    private AuthDecryptor dec;
    private PRGen noncePrg;
    private byte[] nonce = new byte[AuthEncryptor.NONCE_SIZE_BYTES];

    public SecureChannel(InputStream inStr, OutputStream outStr,
            PRGen rand, boolean iAmServer,
            RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key

        super(inStr, outStr);
        // IMPLEMENT THIS

        KeyExchange ke = new KeyExchange(rand, iAmServer);
        byte[] key;

        if (iAmServer) {
            byte[] keClient = serverKey.decrypt(super.receiveMessage());
            key = ke.processInMessage(keClient);
            if (key == null) {
                System.out.println("1");
                close();
                return;
            }
            byte[] keServer = ke.prepareOutMessage();

            super.sendMessage(serverKey.encrypt(keServer, rand));
            super.sendMessage(serverKey.sign(concatenate(keClient, keServer), rand));

        } else {
            byte[] keClient = ke.prepareOutMessage();
            super.sendMessage(serverKey.encrypt(keClient, rand));

            byte[] keServer = serverKey.decrypt(super.receiveMessage());
            if (!serverKey.verifySignature(concatenate(keClient, keServer), super.receiveMessage())) {
                System.out.println("3");
                close();
                return;
            }

            key = ke.processInMessage(keServer);
            if (key == null) {
                System.out.println("2");
                close();
                return;
            }
        }

        enc = new AuthEncryptor(key);
        dec = new AuthDecryptor(key);
        noncePrg = new PRGen(key);
        noncePrg.nextBytes(nonce);
    }

    // concatenates <a> and <b> into a new array
    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] concatenated = new byte[a.length + b.length];
        System.arraycopy(a, 0, concatenated, 0, a.length);
        System.arraycopy(b, 0, concatenated, a.length, b.length);
        return concatenated;
    }

    public void sendMessage(byte[] message) throws IOException {
        super.sendMessage(enc.authEncrypt(message, nonce, false)); // IMPLEMENT THIS
        noncePrg.nextBytes(nonce);
    }

    public byte[] receiveMessage() throws IOException {
        byte[] inMessage = dec.authDecrypt(super.receiveMessage(), nonce);
        if (inMessage == null)
            return null;
        noncePrg.nextBytes(nonce);
        return inMessage;
    }


    public static void main(String[] args) {
        PRGen rand = new PRGen(new byte[PRGen.KEY_SIZE_BYTES]);
        RSAKeyPair rsakp = new RSAKeyPair(rand, 500);
        RSAKey publicKey = rsakp.getPublicKey();
        RSAKey privateKey = rsakp.getPrivateKey();

        byte[] message = new byte[]{1, 2, 3};
        byte[] signature = publicKey.sign(message, rand);
        assert privateKey.verifySignature(message, signature);
    }
}
