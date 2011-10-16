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

import java.nio.ByteBuffer;

import net.ninthtest.crypto.MessageAuthenticationException;
import org.junit.Test;

/**
 * The unit test case for {@link HelixDecryption}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixDecryptionTest implements HelixTestVectors {
    /* tests for HelixDecryption#HelixDecryption(byte[], byte[]) */

    /**
     * Asserts that {@link HelixDecryption#HelixDecryption(byte[], byte[])}
     * succeeds with a valid key and nonce.
     * 
     * <p>
     * This method exists so that the <tt>HelixDecryption</tt> constructor is
     * exercised. Refer to {@link HelixImplTest} for more exhaustive tests of
     * the <tt>HelixPrimitive</tt> constructor.
     * </p>
     */
    @Test
    @SuppressWarnings("unused")
    public void initAcceptsKeyAndNonce() {
        new HelixDecryption(new byte[32], new byte[16]);
    }

    /* tests for HelixDecryption#HelixDecryption(byte[], byte[], byte[]) */

    /**
     * Asserts that
     * {@link HelixDecryption#HelixDecryption(byte[], byte[], byte[])} rejects
     * a <tt>null</tt> expected MAC.
     */
    @Test
    @SuppressWarnings("unused")
    public void initAcceptsKeyAndNonceAndNullMac() {
        new HelixDecryption(new byte[32], new byte[16], null);
    }

    /**
     * Asserts that
     * {@link HelixDecryption#HelixDecryption(byte[], byte[], byte[])} rejects
     * an expected MAC shorter than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    @SuppressWarnings("unused")
    public void initRejectsMacShorterThan16Bytes() {
        new HelixDecryption(new byte[32], new byte[16], new byte[15]);
    }

    /**
     * Asserts that
     * {@link HelixDecryption#HelixDecryption(byte[], byte[], byte[])} rejects
     * an expected MAC longer than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    @SuppressWarnings("unused")
    public void initRejectsMacLongerThan16Bytes() {
        new HelixDecryption(new byte[32], new byte[16], new byte[17]);
    }

    /**
     * Asserts that
     * {@link HelixDecryption#HelixDecryption(byte[], byte[], byte[])} succeeds
     * with a valid key, nonce, and expected MAC.
     */
    @Test
    @SuppressWarnings("unused")
    public void initAcceptsKeyAndNonceAndMac() {
        new HelixDecryption(new byte[32], new byte[16], new byte[16]);
    }

    /*
     * tests for HelixDecryption#feed(byte[]) and HelixDecryption#finish(byte[])
     * WITHOUT automatic MAC verification
     */

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * MAC when Helix test vector #1 ciphertext is fed incrementally.
     */
    @Test
    public void decryptByFeeding1() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE]);
        ByteBuffer actualPlainText = ByteBuffer.allocate(TEST_VECTOR_1[PLAINTEXT].length);

        byte[] cipherTextPart = new byte[3];
        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 0, cipherTextPart, 0, 3);
        primitive.feed(cipherTextPart);

        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 3, cipherTextPart, 0, 3);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 6, cipherTextPart, 0, 3);
        actualPlainText.put(primitive.feed(cipherTextPart));

        cipherTextPart = new byte[1];
        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 9, cipherTextPart, 0, 1);
        actualPlainText.put(primitive.finish(cipherTextPart));

        assertArrayEquals(TEST_VECTOR_1[PLAINTEXT], actualPlainText.array());
        assertArrayEquals(TEST_VECTOR_1[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * MAC when Helix test vector #2 ciphertext is fed incrementally.
     */
    @Test
    public void decryptByFeeding2() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE], null);
        ByteBuffer actualPlainText = ByteBuffer.allocate(TEST_VECTOR_2[PLAINTEXT].length);

        byte[] cipherTextPart = new byte[5];
        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 0, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 5, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 10, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 15, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 20, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 25, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        cipherTextPart = new byte[2];
        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 30, cipherTextPart, 0, 2);
        actualPlainText.put(primitive.finish(cipherTextPart));

        assertArrayEquals(TEST_VECTOR_2[PLAINTEXT], actualPlainText.array());
        assertArrayEquals(TEST_VECTOR_2[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * MAC when Helix test vector #3 ciphertext is fed incrementally.
     */
    @Test
    public void decryptByFeeding3() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE]);
        ByteBuffer actualPlainText = ByteBuffer.allocate(TEST_VECTOR_3[PLAINTEXT].length);

        byte[] cipherTextPart = new byte[7];
        System.arraycopy(TEST_VECTOR_3[CIPHERTEXT], 0, cipherTextPart, 0, 7);
        actualPlainText.put(primitive.feed(cipherTextPart));

        cipherTextPart = new byte[6];
        System.arraycopy(TEST_VECTOR_3[CIPHERTEXT], 7, cipherTextPart, 0, 6);
        actualPlainText.put(primitive.feed(cipherTextPart));

        actualPlainText.put(primitive.finish(new byte[0]));

        assertArrayEquals(TEST_VECTOR_3[PLAINTEXT], actualPlainText.array());
        assertArrayEquals(TEST_VECTOR_3[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * MAC when Helix test vector #1 ciphertext is passed in whole to
     * {@link HelixDecryption#finish(byte[])}.
     */
    @Test
    public void decryptAtOnceUsingFinish1() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE], null);
        byte[] actualPlainText = primitive.finish(TEST_VECTOR_1[CIPHERTEXT]);

        assertArrayEquals(TEST_VECTOR_1[PLAINTEXT], actualPlainText);
        assertArrayEquals(TEST_VECTOR_1[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * MAC when Helix test vector #2 ciphertext is passed in whole to
     * {@link HelixDecryption#finish(byte[])}.
     */
    @Test
    public void decryptAtOnceUsingFinish2() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE]);
        byte[] actualPlainText = primitive.finish(TEST_VECTOR_2[CIPHERTEXT]);

        assertArrayEquals(TEST_VECTOR_2[PLAINTEXT], actualPlainText);
        assertArrayEquals(TEST_VECTOR_2[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected ciphertext and
     * MAC when Helix test vector #3 plaintext is passed in whole to
     * {@link HelixDecryption#finish(byte[])}.
     */
    @Test
    public void decryptAtOnceUsingFinish3() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE], null);
        byte[] actualPlainText = primitive.finish(TEST_VECTOR_3[CIPHERTEXT]);

        assertArrayEquals(TEST_VECTOR_3[PLAINTEXT], actualPlainText);
        assertArrayEquals(TEST_VECTOR_3[MAC], primitive.getGeneratedMac());
    }

    /*
     * tests for HelixDecryption#feed(byte[]) and HelixDecryption#finish(byte[])
     * WITH automatic MAC verification
     */

    /**
     * Asserts that {@link HelixDecryption#finish(byte[])} throws
     * {@link MessageAuthenticationException} on MAC mismatch when using
     * automatic MAC verification.
     */
    @Test(expected = MessageAuthenticationException.class)
    public void macMismatchThrowsException() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE], new byte[16]);
        primitive.finish(TEST_VECTOR_3[CIPHERTEXT]);
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * passes automatic MAC verification when Helix test vector #1 ciphertext is
     * fed incrementally.
     */
    @Test
    public void decryptAndVerifyByFeeding1() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE], TEST_VECTOR_1[MAC]);
        ByteBuffer actualPlainText = ByteBuffer.allocate(TEST_VECTOR_1[PLAINTEXT].length);

        byte[] cipherTextPart = new byte[3];
        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 0, cipherTextPart, 0, 3);
        primitive.feed(cipherTextPart);

        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 3, cipherTextPart, 0, 3);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 6, cipherTextPart, 0, 3);
        actualPlainText.put(primitive.feed(cipherTextPart));

        cipherTextPart = new byte[1];
        System.arraycopy(TEST_VECTOR_1[CIPHERTEXT], 9, cipherTextPart, 0, 1);
        // will throw MessageAuthenticationException if MAC verification fails
        actualPlainText.put(primitive.finish(cipherTextPart));

        assertArrayEquals(TEST_VECTOR_1[PLAINTEXT], actualPlainText.array());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * passes automatic MAC verification when Helix test vector #2 ciphertext is
     * fed incrementally.
     */
    @Test
    public void decryptAndVerifyByFeeding2() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE], TEST_VECTOR_2[MAC]);
        ByteBuffer actualPlainText = ByteBuffer.allocate(TEST_VECTOR_2[PLAINTEXT].length);

        byte[] cipherTextPart = new byte[5];
        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 0, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 5, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 10, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 15, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 20, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 25, cipherTextPart, 0, 5);
        actualPlainText.put(primitive.feed(cipherTextPart));

        cipherTextPart = new byte[2];
        System.arraycopy(TEST_VECTOR_2[CIPHERTEXT], 30, cipherTextPart, 0, 2);
        // will throw MessageAuthenticationException if MAC verification fails
        actualPlainText.put(primitive.finish(cipherTextPart));

        assertArrayEquals(TEST_VECTOR_2[PLAINTEXT], actualPlainText.array());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * passes automatic MAC verification when Helix test vector #3 ciphertext is
     * fed incrementally.
     */
    @Test
    public void decryptAndVerifyByFeeding3() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        ByteBuffer actualPlainText = ByteBuffer.allocate(TEST_VECTOR_3[PLAINTEXT].length);

        byte[] cipherTextPart = new byte[7];
        System.arraycopy(TEST_VECTOR_3[CIPHERTEXT], 0, cipherTextPart, 0, 7);
        actualPlainText.put(primitive.feed(cipherTextPart));

        cipherTextPart = new byte[6];
        System.arraycopy(TEST_VECTOR_3[CIPHERTEXT], 7, cipherTextPart, 0, 6);
        actualPlainText.put(primitive.feed(cipherTextPart));

        // will throw MessageAuthenticationException if MAC verification fails
        actualPlainText.put(primitive.finish(new byte[0]));

        assertArrayEquals(TEST_VECTOR_3[PLAINTEXT], actualPlainText.array());
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * passes automatic MAC verification when Helix test vector #1 ciphertext is
     * passed in whole to {@link HelixDecryption#finish(byte[])}.
     */
    @Test
    public void decryptAndVerifyAtOnceUsingFinish1() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE], TEST_VECTOR_1[MAC]);
        // will throw MessageAuthenticationException if MAC verification fails
        byte[] actualPlainText = primitive.finish(TEST_VECTOR_1[CIPHERTEXT]);

        assertArrayEquals(TEST_VECTOR_1[PLAINTEXT], actualPlainText);
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * passes automatic MAC verification when Helix test vector #2 ciphertext is
     * passed in whole to {@link HelixDecryption#finish(byte[])}.
     */
    @Test
    public void decryptAndVerifyAtOnceUsingFinish2() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE], TEST_VECTOR_2[MAC]);
        // will throw MessageAuthenticationException if MAC verification fails
        byte[] actualPlainText = primitive.finish(TEST_VECTOR_2[CIPHERTEXT]);

        assertArrayEquals(TEST_VECTOR_2[PLAINTEXT], actualPlainText);
    }

    /**
     * Asserts that {@link HelixDecryption} produces the expected plaintext and
     * passes automatic MAC verification when Helix test vector #3 ciphertext is
     * passed in whole to {@link HelixDecryption#finish(byte[])}.
     */
    @Test
    public void decryptAndVerifyAtOnceUsingFinish3() {
        HelixDecryption primitive = new HelixDecryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        // will throw MessageAuthenticationException if MAC verification fails
        byte[] actualPlainText = primitive.finish(TEST_VECTOR_3[CIPHERTEXT]);

        assertArrayEquals(TEST_VECTOR_3[PLAINTEXT], actualPlainText);
    }
}
