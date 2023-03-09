package com.princeton.authkey;

import com.princeton.random.*;
import com.princeton.asymmetric.*;

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
        byte[] key = null;

        super.sendMessage(ke.prepareOutMessage());
        byte[] inMessage = super.receiveMessage();
        if (inMessage != null) {
            key = ke.processInMessage(inMessage);
        }

        if (iAmServer) {
            super.sendMessage(key != null ? serverKey.sign(key, rand) : new byte[] {});
        } else {
            byte[] signature = super.receiveMessage();
            if (signature == null || key != null && !serverKey.verifySignature(key, signature))
                key = null;
        }

        if (key == null) {
            close();
            return;
        }

        enc = new AuthEncryptor(key);
        dec = new AuthDecryptor(key);

        PRGen prg = new PRGen(key);
        prg.nextBytes(key);

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
        super.sendMessage(encrypted);
        nonceOutPrg.nextBytes(nonceOut);
    }

    public byte[] receiveMessage() throws IOException {
        // IMPLEMENT THIS
        byte[] inMessage = decrypt(super.receiveMessage());
        if (inMessage == null)
            close();

        nonceInPrg.nextBytes(nonceIn);
        return inMessage;
    }

}
