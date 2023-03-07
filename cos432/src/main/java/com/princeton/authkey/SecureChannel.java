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
    private PRGen nonceInPrg;
    private PRGen nonceOutPrg;
    private byte[] nonceIn = new byte[AuthEncryptor.NONCE_SIZE_BYTES];
    private byte[] nonceOut = new byte[AuthEncryptor.NONCE_SIZE_BYTES];

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
            byte[] received = super.receiveMessage();
            byte[] keClient = serverKey.decrypt(received);
            System.out.println("wtf1: received = " + Arrays.toString(received));
            System.out.println("wtf1: keClient = " + Arrays.toString(keClient));
            if (keClient == null) {
                System.out.println("oh no!2");
                super.sendMessage(new byte[] {});
                System.out.println("sent empty string");
                close();
                throw new IOException();
            }
            System.out.println("wtf2");
            System.out.println("keClient: " + Arrays.toString(keClient));
            key = ke.processInMessage(keClient);
            System.out.println("wtf2.1");
            if (key == null) {
                System.out.println("1");
                close();
                throw new IOException();
            }
            System.out.println("wtf2.2");
            byte[] keServer = ke.prepareOutMessage();

            System.out.println("wtf3");
            super.sendMessage(serverKey.encrypt(keServer, rand));
            System.out.println("wtf4");
            super.sendMessage(serverKey.sign(concatenate(keClient, keServer), rand));
            System.out.println("wtf5");

        } else {
            byte[] keClient = ke.prepareOutMessage();
            byte[] keClientEncrypted = serverKey.encrypt(keClient, rand);
            System.out.println("wtf6: keClient = " + Arrays.toString(keClient));
            System.out.println("wtf6: keClientEncrypted = " + Arrays.toString(keClientEncrypted));
            super.sendMessage(keClientEncrypted);
            System.out.println("wtf7");

            System.out.println("wtf8");
            byte[] keServer = serverKey.decrypt(super.receiveMessage());
            if (keServer == null) {
                System.out.println("oh no!");
                close();
                throw new IOException();
            }
            System.out.println("wtf9");
            if (!serverKey.verifySignature(concatenate(keClient, keServer), super.receiveMessage())) {
                System.out.println("3");
                close();
                throw new IOException();
            }
            System.out.println("wtf0");

            key = ke.processInMessage(keServer);
            if (key == null) {
                System.out.println("2");
                close();
                throw new IOException();
            }
        }

        enc = new AuthEncryptor(key);
        dec = new AuthDecryptor(key);

        PRGen prg = new PRGen(key);
        byte[] nonceKey = new byte[PRGen.KEY_SIZE_BYTES];

        if (iAmServer) {
            prg.nextBytes(nonceKey);
            nonceInPrg = new PRGen(nonceKey);
            prg.nextBytes(nonceKey);
            nonceOutPrg = new PRGen(nonceKey);
        } else {
            prg.nextBytes(nonceKey);
            nonceOutPrg = new PRGen(nonceKey);
            prg.nextBytes(nonceKey);
            nonceInPrg = new PRGen(nonceKey);
        }

        nonceInPrg.nextBytes(nonceIn);
        nonceOutPrg.nextBytes(nonceOut);

        System.out.println("iAmServer: " + iAmServer + "; nonceIn: " + Arrays.toString(nonceIn));
        System.out.println("iAmServer: " + iAmServer + "; nonceOut: " + Arrays.toString(nonceOut));
    }

    // concatenates <a> and <b> into a new array
    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] concatenated = new byte[a.length + b.length];
        System.arraycopy(a, 0, concatenated, 0, a.length);
        System.arraycopy(b, 0, concatenated, a.length, b.length);
        return concatenated;
    }

    public void sendMessage(byte[] message) throws IOException {
        byte[] encrypted = enc.authEncrypt(message, nonceOut, false);
        System.out.println("Sending message = " + Arrays.toString(message));
        System.out.println("\tnonce: " + Arrays.toString(nonceOut));
        System.out.println("\tencrypted: " + Arrays.toString(encrypted));

        nonceOutPrg.nextBytes(nonceOut); // maybe need to lock with encryption?
        super.sendMessage(encrypted); // IMPLEMENT THIS
    }

    public byte[] receiveMessage() throws IOException {
        byte[] received = super.receiveMessage();
        byte[] inMessage = dec.authDecrypt(received, nonceIn);
        System.out.println("Receiving message = " + Arrays.toString(received));
        System.out.println("\tnonce: " + Arrays.toString(nonceIn));
        System.out.println("\tdecrypted: " + Arrays.toString(inMessage));
        if (inMessage == null) {
            close();
            throw new IOException();
        }
        nonceInPrg.nextBytes(nonceIn);
        return inMessage;
    }

    public static void main(String[] args) {
        PRGen rand = new PRGen(new byte[PRGen.KEY_SIZE_BYTES]);
        RSAKeyPair rsakp = new RSAKeyPair(rand, 500);
        RSAKey publicKey = rsakp.getPublicKey();
        RSAKey privateKey = rsakp.getPrivateKey();

        byte[] message = new byte[] { 1, 2, 3 };
        byte[] signature = publicKey.sign(message, rand);
        assert privateKey.verifySignature(message, signature);
    }
}
