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

        byte[] key;

        if (iAmServer) {
            KeyExchange ke = new KeyExchange(rand, iAmServer);
            byte[] keInMessage = super.receiveMessage();
            key = ke.processInMessage(keInMessage);
            byte[] keOutMessage = ke.prepareOutMessage();

            byte[] returnMessage = new byte[keOutMessage.length + keInMessage.length];
            System.arraycopy(keInMessage, 0, returnMessage, 0, keInMessage.length);
            System.arraycopy(keOutMessage, 0, returnMessage, keInMessage.length, keOutMessage.length);

            super.sendMessage(serverKey.encrypt(returnMessage, rand));
            super.sendMessage(serverKey.sign(returnMessage, rand));

        } else {
            KeyExchange ke = new KeyExchange(rand, iAmServer);
            byte[] outMessage = ke.prepareOutMessage();
            super.sendMessage(serverKey.encrypt(outMessage, rand));

            byte[] inMessage = serverKey.decrypt(super.receiveMessage());
            byte[] recoveredOutMessage = new byte[outMessage.length];
            System.arraycopy(inMessage, 0, recoveredOutMessage, 0, outMessage.length);

            if (serverKey.verifySignature(inMessage, super.receiveMessage())
                    || !Arrays.equals(recoveredOutMessage, outMessage)) {
                close();
                return;
            }

            byte[] keInMessage = new byte[inMessage.length - outMessage.length];
            System.arraycopy(inMessage, outMessage.length, keInMessage, 0, inMessage.length - outMessage.length);
            key = ke.processInMessage(keInMessage);

        }

        enc = new AuthEncryptor(key);
        dec = new AuthDecryptor(key);
        noncePrg = new PRGen(key);
        noncePrg.nextBytes(nonce);
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
}
