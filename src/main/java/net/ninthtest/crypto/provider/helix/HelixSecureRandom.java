/*
 * Copyright (c) 2011-2014 Matthew Zipay <mattz@ninthtest.net>
 * 
 * This file is part of the NinthTest JCA Provider.
 * 
 * The NinthTest JCA Provider is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * The NinthTest JCA Provider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * the NinthTest JCA Provider. If not, see <http://www.gnu.org/licenses/>.
 */

package net.ninthtest.crypto.provider.helix;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.concurrent.locks.ReentrantLock;

import net.ninthtest.crypto.helix.HelixEncryption;
import net.ninthtest.crypto.helix.HelixPrimitive;
import net.ninthtest.security.Messages;
import net.ninthtest.security.provider.NinthTestProvider;

/**
 * This class is a pseudo-random number generator (PRNG) that uses the Helix key
 * stream as a source of randomness.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public final class HelixSecureRandom extends SecureRandomSpi {
    /* the universal serialization version ID for HelixSecureRandom */
    private static final long serialVersionUID = 6434335112922503291L;

    /* the mutex that guards access to the internal state */
    private final ReentrantLock lock = new ReentrantLock();

    /*
     * the current seed (a 48-byte array consisting of the current Helix secret
     * key and nonce)
     */
    private final byte[] seedState = new byte[48];

    /* the internal Helix primitive used to generate psuedo-random bytes */
    private HelixPrimitive primitive;

    /*
     * The "leftover" pseudo-random bytes from a prior call to
     * #engineNextBytes(byte[]).
     * 
     * Internally, this PRNG generates pseudo-random bytes in blocks of eight
     * (8), which corresponds to the size of a long (the type used for the
     * internal counter). When a request is made for a number of pseudo-random
     * bytes that is NOT a multiple of eight (8), anywhere from one (1) to seven
     * (7) bytes will be internally buffered and used to satisfy subsequent
     * requests.
     */
    private byte[] buffer = new byte[0];

    /*
     * the internal counter that functions as the "plaintext" input to the Helix
     * primitive
     */
    private long counter;

    /**
     * Creates a new <tt>HelixSecureRandom</tt> and performs the provider
     * self-integrity check.
     */
    public HelixSecureRandom() {
        NinthTestProvider.doSelfIntegrityCheck();
    }

    /**
     * Returns the specified number of pseudo-random seed bytes.
     * 
     * @param numBytes
     *            the number of seed bytes to generate (positive whole number or
     *            zero)
     * @return a byte array of length <tt>numBytes</tt>
     * @see java.security.SecureRandomSpi#engineGenerateSeed(int)
     */
    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes < 0) {
            throw new IllegalArgumentException(Messages.getMessage("error.number_of_bytes_is_not_valid"));
        } else if (0 == numBytes) {
            return new byte[0];
        }

        byte[] seed = new byte[numBytes];
        engineNextBytes(seed);

        return seed;
    }

    /**
     * Generates a user-specified number of random bytes.
     * 
     * @param bytes
     *            the array to be filled in with random bytes
     * @see java.security.SecureRandomSpi#engineNextBytes(byte[])
     */
    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException(Messages.getMessage("error.bytes_array_is_required"));
        } else if (bytes.length == 0) {
            return;
        }

        lock.lock();
        try {
            if (primitive == null) {
                initializePrimitive(null);
            }

            if (bytes.length <= buffer.length) {
                System.arraycopy(buffer, 0, bytes, 0, bytes.length);

                // now update the buffer
                if (bytes.length < buffer.length) {
                    byte[] newBuffer = new byte[buffer.length - bytes.length];
                    System.arraycopy(buffer, bytes.length, newBuffer, 0, newBuffer.length);
                    buffer = newBuffer;
                } else {
                    buffer = new byte[0];
                }

                // return early since the buffer satisfied the request
                return;
            }

            int needBytes = bytes.length - buffer.length;
            /*
             * the minimum number of longs that will produce the number of bytes
             * needed to fulfill the request
             */
            int needLongs = (needBytes + 8 - 1) / 8;
            long[] longs = new long[needLongs];
            for (int i = 0; i < needLongs; ++i) {
                longs[i] = counter++;
            }

            byte[] counterBytes = longsToBytes(longs);
            byte[] pseudoRandomBytes = primitive.feed(counterBytes);

            // create the pool of bytes used to fulfill the request
            byte[] pool = new byte[buffer.length + pseudoRandomBytes.length];
            System.arraycopy(buffer, 0, pool, 0, buffer.length);
            System.arraycopy(pseudoRandomBytes, 0, pool, buffer.length, pseudoRandomBytes.length);

            // fulfill the request
            System.arraycopy(pool, 0, bytes, 0, bytes.length);

            // now update the buffer
            buffer = new byte[pool.length - bytes.length];
            System.arraycopy(pool, bytes.length, buffer, 0, buffer.length);
        } finally {
            lock.unlock();
        }
    }

    /* Initializes (or re-initializes) the internal Helix primitive. */
    private void initializePrimitive(final byte[] seed) {
        /*
         * use platform default PRNG (usually SHA1PRNG unless NativePRNG is
         * registered) and the internal seeding mechanism (by immediately
         * calling nextBytes)
         */
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(new byte[23]); // discarded

        byte[] supplement = null;
        if ((null == seed) || (seed.length == 0)) {
            supplement = new byte[seedState.length];
            prng.nextBytes(supplement);
        } else if (seed.length < seedState.length) {
            supplement = new byte[seedState.length];
            System.arraycopy(seed, 0, supplement, 0, seed.length);
            // add random bytes to get a length of 48 (32 key + 16 nonce)
            byte[] more = new byte[seedState.length - seed.length];
            prng.nextBytes(more);
            System.arraycopy(more, 0, supplement, seed.length, more.length);
        } else {
            supplement = new byte[seed.length];
            System.arraycopy(seed, 0, supplement, 0, seed.length);
        }

        lock.lock();
        try {
            if (primitive != null) {
                primitive.finish(new byte[0]);
                primitive = null;
            }

            int i = prng.nextInt(seedState.length);
            for (byte b : supplement) {
                seedState[i++] ^= b;

                if (seedState.length == i) {
                    // wrap around to the beginning and continue
                    i = 0;
                }
            }

            byte[] key = new byte[32];
            System.arraycopy(seedState, 0, key, 0, 32);

            byte[] nonce = new byte[16];
            System.arraycopy(seedState, 32, nonce, 0, 16);

            primitive = new HelixEncryption(key, nonce);
        } finally {
            lock.unlock();

            // always clear the buffer when the primitive is (re)initialized
            buffer = new byte[0];
        }
    }

    /*
     * Converts an array of 64-bit long integers into an array of bytes.
     * 
     * The returned bytes array is a contiguous block of 8-byte sequences
     * representing long integers (least-significant bytes first).
     */
    private byte[] longsToBytes(final long[] longs) {
        int lx = 0;
        int ly = longs.length;
        int bx = 0;

        byte[] bytes = new byte[ly * 8];

        while (lx < ly) {
            bytes[bx++] = (byte) longs[lx];
            bytes[bx++] = (byte) (longs[lx] >> 8);
            bytes[bx++] = (byte) (longs[lx] >> 16);
            bytes[bx++] = (byte) (longs[lx] >> 24);
            bytes[bx++] = (byte) (longs[lx] >> 32);
            bytes[bx++] = (byte) (longs[lx] >> 40);
            bytes[bx++] = (byte) (longs[lx] >> 48);
            bytes[bx++] = (byte) (longs[lx] >> 56);
            ++lx;
        }

        return bytes;
    }

    /**
     * (Re-)Seeds this pseudo-random number generator.
     * <p>
     * The <tt>seed</tt> argument is used to <i>supplement</i> (not replace) the
     * existing seed so that repeated calls do not reduce randomness.
     * </p>
     * <p>
     * If <tt>seed</tt> is empty, this method will effectively use the internal
     * seeding mechanism to see the PRNG.
     * </p>
     * 
     * @param seed
     *            new bytes used to supplement the existing seed value
     * @see java.security.SecureRandomSpi#engineSetSeed(byte[])
     */
    @Override
    protected void engineSetSeed(final byte[] seed) {
        if (seed == null) {
            throw new IllegalArgumentException(Messages.getMessage("error.bytes_array_is_required"));
        }

        initializePrimitive(seed);
    }
}
