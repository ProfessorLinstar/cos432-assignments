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
            key = ke.processInMessage(super.receiveMessage());
            super.sendMessage(ke.prepareOutMessage());
            super.sendMessage(key != null ? serverKey.sign(key, rand) : new byte[] {});

        } else {
            super.sendMessage(ke.prepareOutMessage());
            key = ke.processInMessage(super.receiveMessage());
            if (!serverKey.verifySignature(key, super.receiveMessage()))
                key = null;

        }

        if (key == null) {
            close();
            System.out.println("failed!");
            return;
        }

        enc = new AuthEncryptor(key);
        dec = new AuthDecryptor(key);

        PRGen prg = new PRGen(key);
        byte[] nonceInKey = new byte[PRGen.KEY_SIZE_BYTES];
        byte[] nonceOutKey = new byte[PRGen.KEY_SIZE_BYTES];
        if (iAmServer) {
            prg.nextBytes(nonceInKey);
            prg.nextBytes(nonceOutKey);
        } else {
            prg.nextBytes(nonceOutKey);
            prg.nextBytes(nonceInKey);
        }

        nonceInPrg = new PRGen(key);
        nonceOutPrg = new PRGen(key);

        nonceInPrg.nextBytes(nonceIn);
        nonceOutPrg.nextBytes(nonceOut);
    }

    // checks whether or not the nonce at the end of <message> matches
    // this.nonceIn. if nonce matches, then uses this.dec to decrypt the
    // message and returns the result. otherwise returns null.
    private byte[] decrypt(byte[] message) {
        System.out.println("Receiving message = " + Arrays.toString(message));
        System.out.println("\tnonce: " + Arrays.toString(nonceIn));

        if (message.length < nonceIn.length)
            return null;
        for (int i = 0; i < nonceIn.length; i++) {
            if (message[message.length - nonceIn.length + i] != nonceIn[i])
                return null;
        }
        return dec.authDecrypt(message);
    }

    public void sendMessage(byte[] message) throws IOException {
        // IMPLEMENT THIS
        byte[] encrypted = enc.authEncrypt(message, nonceOut, true);
        System.out.println("Sending message = " + Arrays.toString(message));
        System.out.println("\tnonce: " + Arrays.toString(nonceOut));
        System.out.println("\tencrypted: " + Arrays.toString(encrypted));

        super.sendMessage(encrypted);
        nonceOutPrg.nextBytes(nonceOut);
    }

    public byte[] receiveMessage() throws IOException {
        // IMPLEMENT THIS
        byte[] inMessage = decrypt(super.receiveMessage());
        System.out.println("\tdecrypted: " + Arrays.toString(inMessage));

        if (inMessage == null)
            close();

        nonceInPrg.nextBytes(nonceIn);
        return inMessage;
    }

}
