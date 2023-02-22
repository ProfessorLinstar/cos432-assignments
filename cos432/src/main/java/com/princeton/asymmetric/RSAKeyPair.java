package com.princeton.asymmetric;

import com.princeton.random.*;

import java.math.BigInteger;

/***
 * This class represents a pair of RSA keys to be used for asymmetric
 * encryption.
 */
public class RSAKeyPair {
    private RSAKey publicKey;
    private RSAKey privateKey;

    private BigInteger n;
    private BigInteger p;
    private BigInteger q;
    private BigInteger o;

    private BigInteger d;
    public static BigInteger e = BigInteger.valueOf(65537);

    /***
     * Creates a probable prime which is coprime to e.
     *
     * @param rand PRGen that is used for BigInteger.probablePrime
     * @param numBits size in bits of the prime to be generated
     */
    private static BigInteger probableCoprime(int numBits, PRGen rand) {
        BigInteger p;
        do {
            p = BigInteger.probablePrime(numBits, rand);
        } while (p.mod(e).equals(BigInteger.ONE));
        return p;
    }

    /***
     * Create an RSA key pair.
     *
     * @param rand    PRGen that this class can use to get pseudorandom bits
     * @param numBits size in bits of each of the primes that will be used
     */
    public RSAKeyPair(PRGen rand, int numBits) {
        // IMPLEMENT THIS

        p = probableCoprime(numBits, rand);
        q = probableCoprime(numBits, rand);

        n = p.multiply(q);
        o = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        d = e.modInverse(o);

        publicKey = new RSAKey(e, n);
        privateKey = new RSAKey(d, n);
    }

    /***
     * Get the public key from this keypair.
     *
     * @return public RSAKey corresponding to this pair
     */
    public RSAKey getPublicKey() {
        return publicKey;
    }

    /***
     * Get the private key from this keypair.
     *
     * @return private RSAKey corresponding to this pair
     */
    public RSAKey getPrivateKey() {
        return privateKey;
    }

    /***
     * Get an array containing the two primes that were used in this KeyPair's
     * generation. In real life, this wouldn't
     * usually be necessary (we don't always keep track of the primes used for
     * generation). Including this function here
     * is for grading purposes.
     *
     * @return two-element array of BigIntegers containing both of the primes used
     *         to generate this KeyPair
     */
    public BigInteger[] getPrimes() {
        BigInteger[] primes = new BigInteger[2];

        // IMPLEMENT THIS
        primes[0] = p;
        primes[1] = q;

        return primes;
    }

    public static void main(String[] args) {
        PRGen prg = new PRGen(new byte[] { 1 });
        for (int i = 0; i < 100; i++) {
            System.out.println("******");
            System.out.println("Attempt " + i);
            RSAKeyPair rsaKP = new RSAKeyPair(prg, 256);
            System.out.println("rsaKP.getPrimes: ");
            for (BigInteger b : rsaKP.getPrimes()) {
                System.out.println("\t" + b);
            }
            System.out.println("rsaKP.p: " + rsaKP.p);
            System.out.println("rsaKP.q: " + rsaKP.q);
            System.out.println("rsaKP.o: " + rsaKP.o);
            System.out.println("rsaKP.n: " + rsaKP.n);
            System.out.println("rsaKP.d: " + rsaKP.d);
            System.out.println("RSAKeyPair.e: " + RSAKeyPair.e);

            System.out.println("rsaKP.d * RSAKeyPair.e mod rsaKP.o: " + rsaKP.d.multiply(RSAKeyPair.e).mod(rsaKP.o));

            System.out.println("******");
            System.out.println();
        }

        // PRGen prg = new PRGen(new byte[] { 0 });
        // for (int i = 0; i < 100; i++) {
        // System.out.println("probable prime: "
        // + Integer.toBinaryString(Integer.parseInt(BigInteger.probablePrime(10,
        // prg).toString())));
        // }
    }
}
