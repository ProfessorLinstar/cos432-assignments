package com.princeton.asymmetric; import com.princeton.random.*;

import java.math.BigInteger;

/***
 * This class facilitates a key exchange.
 *
 * Once two {@code KeyExchange} participants (objects) are created, two things have to happen for the key exchange to be
 * complete:
 *  1.  Call {@code prepareOutMessage} on the first participant, and send the result to the other participant.
 *  2.  Receive the result of the second participant's {@code prepareOutMessage}, and pass it into the first
 *      participant's {@code processInMessage} method.
 * The process can happen in an arbitrary order of participants (i.e., it doesn't matter which participant is first).
 * They could even happen concurrently in two separate threads. However, your code must work regardless of the order of
 * participants.
 */
public class KeyExchange {
    public static final int OUTPUT_SIZE_BYTES = PRF.OUTPUT_SIZE_BYTES;
    public static final int OUTPUT_SIZE_BITS = 8 * OUTPUT_SIZE_BYTES;

    // instance variables
    // IMPLEMENT THIS

    /***
     * Prepares to do a key exchange. {@code rand} is a secure pseudorandom generator that can be used by the
     * implementation. {@code iAmServer} is true if and only if this instantiation is playing the server role in the
     * exchange. Each exchange has exactly two participants: one plays the role of client and the other plays the role
     * of server.
     *
     * @param rand secure pseudorandom generator
     * @param iAmServer true iff we are playing the server role in this exchange
     */
    public KeyExchange(PRGen rand, boolean iAmServer) {
        // IMPLEMENT THIS
        throw new RuntimeException("Unimplemented.");
    }

    /***
     * Create a message to send to the other key exchange participant for digest.
     *
     * @return digestible message for sending to the other key exchange participant
     */
    public byte[] prepareOutMessage() {
        // IMPLEMENT THIS
        throw new RuntimeException("Unimplemented.");
    }

    /***
     * Creates a digest from the specified {@code inMessage} from the other key exchange participant.
     *
     * If passed a null value, then throw a {@code NullPointerException}.
     * Otherwise, if passed a value that could not possibly have been generated
     *    by {@code prepareOutMessage}, then return null.
     * Otherwise, return a "digest" (hash) with the property described below.
     *
     * This code must provide the following security guarantee: If the two
     *    participants end up with the same non-null digest value, then this digest value
     *    is not known to anyone else. This must be true even if third parties
     *    can observe and modify the messages sent between the participants.
     * This code is NOT required to check whether the two participants end up with
     *    the same digest value; the code calling this must verify that property.
     *
     * @param inMessage exchange message from the other key exchange participant
     * @return digest of {@code inMessage} with cryptographic properties as described (the size of the returned array
     * must be {@code OUTPUT_SIZE_BYTES}.
     */
    public byte[] processInMessage(byte[] inMessage) {
        // IMPLEMENT THIS
        throw new RuntimeException("Unimplemented.");
    }
}
