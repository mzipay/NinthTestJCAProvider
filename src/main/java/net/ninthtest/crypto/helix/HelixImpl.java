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

package net.ninthtest.crypto.helix;

import java.util.Arrays;

import net.ninthtest.security.Messages;

/**
 * The implementation of the Helix combined stream cipher and MAC function used
 * by the "NinthTest" security provider.
 * 
 * <p>
 * This implementation is adapted from the Python reference implementation
 * presented in <a href="http://www.ddj.com/security/184405478">Helix: Fast
 * Encryption &amp; Authentication</a> (Dr. Dobb's November 2003).
 * </p>
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 * @see <a href="http://www.schneier.com/paper-helix.html">Helix: Fast
 *      Encryption and Authentication in a Single Cryptographic Primitive</a>
 */
abstract class HelixImpl implements HelixPrimitive {
    /* length of the Helix key in bytes */
    private int lU;

    /* the eight 32-bit working/expanded key words */
    private int[] K;

    /*
     * the Helix "working key" (the key words immediately following key mixing);
     * only populated for the sake of unit testing using the official Helix test
     * vectors
     */
    private byte[] workingKey;

    /* the five 32-bit state words */
    private int[] Z;

    /* the eight 32-bit key material words */
    private int[] X1;

    /* keeps track of the Helix block */
    private int i8;

    /*
     * the generated MAC (after a successful encryption or decryption operation)
     */
    private byte[] T;

    /*
     * buffers "extra" bytes between calls to the #feed(byte[]) method
     * 
     * HelixImpl only processes data in whole-word (four-byte) increments at a
     * time; if the number of fed bytes is not a multiple of four, up to three
     * bytes are buffered for the next call.
     */
    private byte[] buffer;

    /*
     * the total number of bytes encrypted or decrypted (needed by the MAC
     * function)
     */
    private int totalLength;

    /*
     * whether or not this primitive's state has been cleared.
     * 
     * A HelixImpl is only usable for a single encryption or decryption
     * operation, after which its internal state is cleared. If stateIsCleared
     * is true when #feed(byte[]), #bufferSize(), or #finish(byte[]) is called,
     * an IllegalStateException is thrown.
     */
    private boolean stateIsCleared;

    /* Performs the initial key and nonce mixing. */
    HelixImpl(final byte[] U, final byte[] N) {
        if ((U == null) || (U.length > 32)) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.invalid_key"));
        } else if ((N == null) || (N.length != 16)) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.invalid_nonce"));
        }

        lU = U.length;

        K = new int[8];
        Z = new int[5];
        X1 = new int[8];

        if (32 == lU) {
            bytesToInts(U, 0, 32, K, 0);
        } else {
            // expand key to 32 bytes
            byte[] extendedInputKey = new byte[32];
            System.arraycopy(U, 0, extendedInputKey, 0, lU);
            bytesToInts(extendedInputKey, 0, 32, K, 0);
        }

        /*
         * initialize Helix state for encryption or decryption (key mixing
         * yields the "working key," used for unit testing with the official
         * Helix test vectors)
         */
        workingKey = keyMixing();
        nonceMixing(N);
    }

    /*
     * Converts the expanded key to the working key (K) using the Helix block
     * function.
     */
    private byte[] keyMixing() {
        int lUPlus64 = lU + 64;
        int[] words = new int[8];

        for (int i = 0; i < 8; ++i) {
            System.arraycopy(K, 0, Z, 0, 4);
            Z[4] = lUPlus64;

            blockFunction(0, 0, 0);

            System.arraycopy(K, 0, words, 0, 8);

            K[0] = words[4] ^ Z[0];
            K[1] = words[5] ^ Z[1];
            K[2] = words[6] ^ Z[2];
            K[3] = words[7] ^ Z[3];

            System.arraycopy(words, 0, K, 4, 4);
        }

        /*
         * return the "working key" (for unit testing using the official Helix
         * test vectors)
         */
        return intsToBytes(K);
    }

    /*
     * Expand the nonce to eight words (32-bit integers) and mix using the Helix
     * block function.
     */
    private void nonceMixing(final byte[] N) {
        // expand the nonce
        int[] nonceWords = new int[8];
        bytesToInts(N, 0, 16, nonceWords, 0);

        for (int i = 0; i < 4; ++i) {
            nonceWords[i + 4] = (i - nonceWords[i]);
        }

        int x = 0;
        for (int i = 0; i < 8; ++i) {
            x = ((i % 4) == 1) ? 4 * lU : 0;
            X1[i] = K[(i + 4) % 8] + nonceWords[i] + x;
        }

        Z[0] = (K[3] ^ nonceWords[0]);
        Z[1] = (K[4] ^ nonceWords[1]);
        Z[2] = (K[5] ^ nonceWords[2]);
        Z[3] = (K[6] ^ nonceWords[3]);
        Z[4] = K[7];

        i8 = 0;

        for (int i = 0; i < 8; ++i) {
            doBlock(0);
        }
    }

    /*
     * Converts an array of bytes into an array of 32-bit integers.
     * 
     * The bytes array is a contiguous block of 4-byte sequences representing
     * integers (least-significant bytes first).
     */
    private int[] bytesToInts(final byte[] bytes) {
        int[] ints = new int[bytes.length / 4];
        bytesToInts(bytes, 0, bytes.length, ints, 0);

        return ints;
    }

    /*
     * Converts an array of bytes into an array of 32-bit integers.
     * 
     * The bytes array is a contiguous block of 4-byte sequences representing
     * integers (least-significant bytes first).
     */
    private void bytesToInts(final byte[] bytes, int bx, final int by, final int[] ints, int ix) {
        int b = bx;
        int i = ix;
        while (b < by) {
            ints[i++] =
                    (bytes[b++] & 0xff) + ((bytes[b++] & 0xff) << 8) + ((bytes[b++] & 0xff) << 16) + (bytes[b++] << 24);
        }
    }

    /*
     * Converts an array of 32-bit integers into an array of bytes.
     * 
     * The returned bytes array is a contiguous block of 4-byte sequences
     * representing integers (least-significant bytes first).
     */
    private byte[] intsToBytes(final int[] ints) {
        int ix = 0;
        int iy = ints.length;
        int bx = 0;

        byte[] bytes = new byte[iy * 4];

        while (ix < iy) {
            bytes[bx++] = (byte) ints[ix];
            bytes[bx++] = (byte) (ints[ix] >> 8);
            bytes[bx++] = (byte) (ints[ix] >> 16);
            bytes[bx++] = (byte) (ints[ix] >> 24);
            ++ix;
        }

        return bytes;
    }

    /*
     * Executes a single block of Helix.
     * 
     * At the end of the block function, the next word of key stream is in Z[0].
     */
    private void blockFunction(final int X_i0, final int X_i1, final int W_i) {
        int z0 = Z[0];
        int z1 = Z[1];
        int z2 = Z[2];
        int z3 = Z[3];
        int z4 = Z[4];

        z0 += z3;
        z3 = (z3 << 15) | (z3 >>> -15);
        z1 += z4;
        z4 = (z4 << 25) | (z4 >>> -25);
        z2 ^= z0;
        z0 = (z0 << 9) | (z0 >>> -9);
        z3 ^= z1;
        z1 = (z1 << 10) | (z1 >>> -10);
        z4 += z2;
        z2 = (z2 << 17) | (z2 >>> -17);

        z0 ^= (z3 + X_i0);
        z3 = (z3 << 30) | (z3 >>> -30);
        z1 ^= z4;
        z4 = (z4 << 13) | (z4 >>> -13);
        z2 += z0;
        z0 = (z0 << 20) | (z0 >>> -20);
        z3 += z1;
        z1 = (z1 << 11) | (z1 >>> -11);
        z4 ^= z2;
        z2 = (z2 << 5) | (z2 >>> -5);

        z0 += (z3 ^ W_i);
        z3 = (z3 << 15) | (z3 >>> -15);
        z1 += z4;
        z4 = (z4 << 25) | (z4 >>> -25);
        z2 ^= z0;
        z0 = (z0 << 9) | (z0 >>> -9);
        z3 ^= z1;
        z1 = (z1 << 10) | (z1 >>> -10);
        z4 += z2;
        z2 = (z2 << 17) | (z2 >>> -17);

        z0 ^= (z3 + X_i1);
        z3 = (z3 << 30) | (z3 >>> -30);
        z1 ^= z4;
        z4 = (z4 << 13) | (z4 >>> -13);
        z2 += z0;
        z0 = (z0 << 20) | (z0 >>> -20);
        z3 += z1;
        z1 = (z1 << 11) | (z1 >>> -11);
        z4 ^= z2;
        z2 = (z2 << 5) | (z2 >>> -5);

        Z[0] = z0;
        Z[1] = z1;
        Z[2] = z2;
        Z[3] = z3;
        Z[4] = z4;
    }

    /**
     * Returns the next state word for use in the main encryption/decryption
     * loop.
     * 
     * @return the state word <tt>Z[0]</tt>.
     */
    protected final int nextStateWord() {
        return Z[0];
    }

    /**
     * Applies a single Helix block to an input word.
     * 
     * @param word
     *            a single word (32-bit integer) of plaintext or ciphertext
     */
    protected final void doBlock(int word) {
        int i = i8 % 8;

        int X_i0 = K[i];

        int X_i1 = X1[i];
        if ((i % 4) == 3) {
            X_i1 += i8 >> 31;
        }
        X_i1 += i8;

        blockFunction(X_i0, X_i1, word);

        i8 += 1;
    }

    /**
     * Processes the next whole number of words (32-bit integers) from
     * <tt>part</tt>.
     * 
     * <p>
     * Up to three bytes at the end of <tt>part</tt> may be buffered for the
     * next call, in order to ensure that only a whole number of words are
     * processed during this call.
     * </p>
     * 
     * @param part
     *            the next sequence of bytes to be processed by this primitive
     * @return an array of bytes representing plaintext or ciphertext, depending
     *         on the operation mode of this primitive
     */
    @Override
    public final byte[] feed(final byte[] part) {
        if (stateIsCleared) {
            throw new IllegalStateException(Messages.getMessage("helix.error.must_reinitialize"));
        }

        return feed(part, 0xffffffff);
    }

    /*
     * Processes the next whole number of words (32-bit integers) from part.
     * 
     * When called by #feed(byte[]), the mask will always be 0xffffffff. When
     * called by #finish(byte[]), the mask will be one of 0x000000ff,
     * 0x0000ffff, or 0x00ffffff (depending on how many "leftover" bytes are
     * buffered).
     */
    private byte[] feed(final byte[] part, int mask) {
        if (part == null) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.input_byte_array_is_required"));
        }

        totalLength += part.length;

        /*
         * the text array will contain any previously-buffered bytes followed by
         * the input bytes
         */
        byte[] text = null;
        if (buffer != null) {
            text = new byte[buffer.length + part.length];
            System.arraycopy(buffer, 0, text, 0, buffer.length);
            System.arraycopy(part, 0, text, buffer.length, part.length);
            /*
             * clear the buffer; it may be re-initialized later, if the number
             * of text bytes does not equate to a whole number of words (32-bit
             * ints)
             */
            buffer = null;
        } else {
            text = new byte[part.length];
            System.arraycopy(part, 0, text, 0, part.length);
        }

        int extra = text.length % 4;
        int processed = text.length - extra;

        /*
         * if any bytes will be unprocessed, buffer them (note that the buffer
         * will ALWAYS be an array of length 1, 2, or 3; or null)
         */
        if (extra != 0) {
            buffer = new byte[extra];
            System.arraycopy(text, processed, buffer, 0, extra);
        }

        /* bail early if there would be no text produced */
        if (0 == processed) {
            return null;
        }

        byte[] inputBytes = new byte[processed];
        System.arraycopy(text, 0, inputBytes, 0, processed);

        int[] inputWords = bytesToInts(inputBytes);
        int[] outputWords = transformWords(inputWords, mask);

        byte[] outputBytes = intsToBytes(outputWords);
        if (outputBytes.length != processed) {
            /*
             * should never happen; outputWords has the same length as
             * inputWords, which is calculated from inputBytes
             */
            throw new IllegalStateException(Messages.getMessage("helix.error.invalid_output_length"));
        }

        return outputBytes;
    }

    /**
     * Performs the main encryption/decryption loop.
     * 
     * @param inputWords
     *            the plaintext words (encryption) or ciphertext words
     *            (decryption)
     * @param mask
     *            a 32-bit mask to apply to each output word (ignored during
     *            encryption)
     * @return the output words (ciphertext words when encrypting, plaintext
     *         words when decrypting)
     */
    protected abstract int[] transformWords(final int[] inputWords, final int mask);

    /**
     * {@inheritDoc}
     * 
     * @return an integer in the range <i>[0..3]</i>
     */
    @Override
    public final int bufferSize() {
        if (stateIsCleared) {
            throw new IllegalStateException(Messages.getMessage("helix.error.must_reinitialize"));
        }

        return (buffer != null) ? buffer.length : 0;
    }

    /**
     * {@inheritDoc}
     * 
     * <p>
     * All remaining bytes (buffered + <tt>part</tt>) are processed. Up to three
     * zero-bytes of padding are added to the remaining bytes to ensure that
     * there is a whole number of words to process. Any padded bytes are masked
     * off when the operation is completed.
     * </p>
     * 
     * <p>
     * If this method completes successfully, the generated MAC can be retrieved
     * using the {@link HelixPrimitive#getGeneratedMac()} method.
     * </p>
     * 
     * @param part
     *            the last input bytes to be fed
     * @return the ciphertext (encryption) or plaintext (decryption) bytes
     */
    @Override
    public byte[] finish(final byte[] part) {
        if (stateIsCleared) {
            throw new IllegalStateException(Messages.getMessage("helix.error.must_reinitialize"));
        }

        byte[] tempText = feed(part);
        if (tempText == null) {
            tempText = new byte[0];
        }

        /*
         * if unprocessed (buffered) bytes remain, process them now with padding
         */
        byte[] remainingText = null;
        if (buffer != null) {
            int pad = 4 - buffer.length;

            byte[] paddedBuffer = new byte[4];
            System.arraycopy(buffer, 0, paddedBuffer, 0, buffer.length);

            int mask = 0;
            switch (buffer.length) {
            case 1:
                mask = 0x000000ff;
                break;
            case 2:
                mask = 0x0000ffff;
                break;
            case 3:
                mask = 0x00ffffff;
                break;
            default:
                /*
                 * should never happen; buffer is always sized based on a mod4
                 * calculation, and is left null if the size would be zero
                 */
                throw new IllegalStateException(Messages.getMessage("helix.error.unexpected_buffer_size"));
            }

            /*
             * clear the buffer; it should NOT be re-initialized after the call
             * to feed() below since the paddedBuffer length is a multiple of
             * four (i.e. it represents a whole number of words)
             */
            buffer = null;

            byte[] remainingPaddedText = feed(paddedBuffer, mask);
            if (buffer != null) {
                /* should never happen; see previous comment */
                throw new IllegalStateException(Messages.getMessage("helix.error.unprocessed_buffer_bytes"));
            }

            remainingText = new byte[remainingPaddedText.length - pad];
            System.arraycopy(remainingPaddedText, 0, remainingText, 0, remainingText.length);

            /* decrease total length by 4 (size of the last byte array fed) */
            totalLength -= 4;
        }

        byte[] outputBytes = null;
        if (remainingText != null) {
            outputBytes = new byte[tempText.length + remainingText.length];
            System.arraycopy(tempText, 0, outputBytes, 0, tempText.length);
            System.arraycopy(remainingText, 0, outputBytes, tempText.length, remainingText.length);
        } else {
            outputBytes = tempText;
        }

        // generate the MAC, then clear the internal state
        T = macFunction();
        clearState();

        return outputBytes;
    }

    /* Generates the MAC after a Helix encryption/decryption operation. */
    private byte[] macFunction() {
        int lengthMod4 = totalLength % 4;

        Z[0] ^= 0x912d94f1;

        for (int i = 0; i < 8; ++i) {
            doBlock(lengthMod4);
        }

        int[] tag = new int[4];
        for (int i = 0; i < 4; ++i) {
            tag[i] = Z[0];
            doBlock(lengthMod4);
        }

        return intsToBytes(tag);
    }

    /**
     * {@inheritDoc}
     * 
     * @return the generated MAC bytes
     * @throws IllegalStateException
     *             if the encryption/decryption operation has not completed
     *             successfully
     */
    @Override
    public final byte[] getGeneratedMac() {
        if (!stateIsCleared || (T == null)) {
            throw new IllegalStateException(Messages.getMessage("helix.error.mac_not_available"));
        }

        byte[] mac = new byte[16];
        System.arraycopy(T, 0, mac, 0, 16);

        return mac;
    }

    /*
     * Zeroes and/or nullifies all internal state following a Helix
     * encryption/decryption operation.
     * 
     * This primitive cannot be used for any further processing after this
     * method has been called. Any attempt will cause IllegalStateException to
     * be thrown.
     */
    private void clearState() {
        lU = 0;

        Arrays.fill(K, 0);
        K = null;

        Arrays.fill(workingKey, (byte) 0);
        workingKey = null;

        Arrays.fill(Z, 0);
        Z = null;

        Arrays.fill(X1, 0);
        X1 = null;

        i8 = 0;

        buffer = null;

        totalLength = 0;

        stateIsCleared = true;
    }

    /*
     * Returns the Helix "working key" (the state of the key words immediately
     * following key mixing).
     * 
     * This method is only intended to be used by unit tests.
     */
    final byte[] getWorkingKey() {
        if (stateIsCleared) {
            throw new IllegalStateException(Messages.getMessage("helix.error.must_reinitialize"));
        }

        byte[] copyOfWorkingKey = new byte[32];
        System.arraycopy(workingKey, 0, copyOfWorkingKey, 0, 32);
        return copyOfWorkingKey;
    }
}
