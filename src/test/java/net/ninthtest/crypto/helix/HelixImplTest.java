/*
 * Copyright (c) 2011 Matthew Zipay <mattz@ninthtest.net>
 * 
 * This file is part of the NinthTest JCA Provider.
 *
 * The NinthTest JCA Provider is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * The NinthTest JCA Provider is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * the NinthTest JCA Provider. If not, see <http://www.gnu.org/licenses/>.
 */

package net.ninthtest.crypto.helix;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;

/**
 * The unit test case for <tt>HelixImpl</tt>.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixImplTest implements HelixTestVectors {
    /*
     * Creates a generic HelixImpl instance for testing.
     * 
     * The instance returned by this method can only be used for testing general
     * behavior, as the implementation of the
     * HelixImpl#transformWords(int[], int) method is intentionally "dumb."
     * Any tests that require a working primitive for encryption or decryption
     * belong in HelixEncryptionTest or HelixDecryptionTest, respectively.
     */
    private static HelixImpl createPrimitive(final byte[] key, final byte[] nonce) {
        return new HelixImpl(key, nonce) {
            @Override
            protected int[] transformWords(int[] inputWords, int mask) {
                return new int[inputWords.length];
            }
        };
    }

    /* tests for HelixImpl#HelixImpl(byte[], byte[]) */

    /**
     * Asserts that <tt>HelixImpl</tt> cannot be instantiated with a
     * <tt>null</tt> key.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNullKey() {
        createPrimitive(null, new byte[16]);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> cannot be instantiated with a key
     * longer than 32 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsKeyLongerThan32Bytes() {
        createPrimitive(new byte[33], new byte[16]);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> can be instantiated with a key
     * shorter than 32 bytes.
     */
    @Test
    public void initAcceptsKeyShorterThan32Bytes() {
        createPrimitive(new byte[17], new byte[16]);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> can be instantiated with a key of
     * exactly 32 bytes.
     */
    @Test
    public void initAcceptsKeyOfExactly32Bytes() {
        createPrimitive(new byte[32], new byte[16]);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> cannot be instantiated with a
     * <tt>null</tt> nonce.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNullNonce() {
        createPrimitive(new byte[32], null);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> cannot be instantiated with a nonce
     * shorter than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNonceShorterThan16Bytes() {
        createPrimitive(new byte[32], new byte[15]);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> cannot be instantiated with a nonce
     * longer than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNonceLongerThan16Bytes() {
        createPrimitive(new byte[32], new byte[17]);
    }

    /**
     * Asserts that <tt>HelixImpl</tt> initializes the expected
     * &quot;working key&quot; using Helix test vector #1.
     */
    @Test
    public void initProducesExpectedWorkingKey1() {
        HelixImpl primitive = createPrimitive(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE]);
        assertArrayEquals(TEST_VECTOR_1[WORKING_KEY], primitive.getWorkingKey());
    }

    /**
     * Asserts that <tt>HelixImpl</tt> initializes the expected
     * &quot;working key&quot; using Helix test vector #2.
     */
    @Test
    public void initProducesExpectedWorkingKey2() {
        HelixImpl primitive = createPrimitive(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE]);
        assertArrayEquals(TEST_VECTOR_2[WORKING_KEY], primitive.getWorkingKey());
    }

    /**
     * Asserts that <tt>HelixImpl</tt> initializes the expected
     * &quot;working key&quot; using Helix test vector #3.
     */
    @Test
    public void initProducesExpectedWorkingKey3() {
        HelixImpl primitive = createPrimitive(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE]);
        assertArrayEquals(TEST_VECTOR_3[WORKING_KEY], primitive.getWorkingKey());
    }

    /* tests for HelixImpl#feed(byte[]) */

    /**
     * Asserts that <tt>HelixImpl#feed(byte[])</tt> rejects a <tt>null</tt>
     * argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void feedRejectsNullArgument() {
        HelixImpl primitive = createPrimitive(new byte[32], new byte[16]);
        primitive.feed(null);
    }

    /**
     * Asserts that <tt>HelixImpl#feed(byte[])</tt> fails if the primitive
     * has already been used to complete an encryption operation.
     */
    @Test(expected = IllegalStateException.class)
    public void feedFailsIfPrimitiveHasAlreadyCompleted() {
        HelixImpl primitive = createPrimitive(new byte[32], new byte[16]);
        primitive.finish(new byte[0]);

        primitive.feed(new byte[0]);
    }

    /**
     * Asserts that <tt>HelixImpl#feed(byte[])</tt> only processes whole
     * words at a time, buffering extra bytes.
     */
    @Test
    public void feedProcessesOnlyWholeWordsOfInput() {
        HelixImpl primitive = createPrimitive(new byte[32], new byte[16]);

        /* the buffer is initially empty */
        assertEquals(0, primitive.bufferSize());

        /* feeding 0 bytes is effectively a no-op */
        byte[] out = primitive.feed(new byte[0]);
        assertNull(out);
        assertEquals(0, primitive.bufferSize());

        /* 0 buffered + 4 fed = 4 processed, 0 buffered */
        out = primitive.feed(new byte[4]);
        assertEquals(4, out.length);
        assertEquals(0, primitive.bufferSize());

        /* 0 buffered + 3 fed = 0 processed, 3 buffered */
        out = primitive.feed(new byte[3]);
        assertNull(out);
        assertEquals(3, primitive.bufferSize());

        /* 3 buffered + 3 fed = 4 processed, 2 buffered */
        out = primitive.feed(new byte[3]);
        assertEquals(4, out.length);
        assertEquals(2, primitive.bufferSize());

        /* 2 buffered + 3 fed = 4 processed, 1 buffered */
        out = primitive.feed(new byte[3]);
        assertEquals(4, out.length);
        assertEquals(1, primitive.bufferSize());

        /* 1 buffered + 3 fed = 4 processed, 0 buffered */
        out = primitive.feed(new byte[3]);
        assertEquals(4, out.length);
        assertEquals(0, primitive.bufferSize());
    }

    /* tests for HelixImpl#finish(byte[]) */

    /**
     * Asserts that <tt>HelixImpl#finish(byte[])</tt> rejects a <tt>null</tt>
     * argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void finishRejectsNullArgument() {
        HelixImpl primitive = createPrimitive(new byte[32], new byte[16]);
        primitive.feed(null);
    }

    /**
     * Asserts that <tt>HelixImpl#finish(byte[])</tt> fails if the
     * primitive has already been used to complete an encryption operation.
     */
    @Test(expected = IllegalStateException.class)
    public void finishFailsIfPrimitiveHasAlreadyCompleted() {
        HelixImpl primitive = createPrimitive(new byte[32], new byte[16]);
        primitive.finish(new byte[0]);

        primitive.finish(new byte[0]);
    }

    /**
     * Asserts that <tt>HelixImpl#finish(byte[])</tt> processes all
     * remaining bytes.
     */
    @Test
    public void finishProcessesAllRemainingBytes() {
        HelixImpl primitive = createPrimitive(new byte[32], new byte[16]);

        /* the buffer is initially empty */
        assertEquals(0, primitive.bufferSize());

        /* there should now be two bytes buffered */
        primitive.feed(new byte[2]);
        assertEquals(2, primitive.bufferSize());

        /*
         * 2 buffered + 4 finished = 8 processed (but mask on last word is
         * 0x0000ffff), 0 buffered
         */
        byte[] out = primitive.finish(new byte[4]);
        assertEquals(6, out.length);
    }
}
