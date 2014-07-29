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

import static org.junit.Assert.assertArrayEquals;

import java.nio.ByteBuffer;

import org.junit.Test;

/**
 * The unit test case for {@link HelixEncryption}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixEncryptionTest implements HelixTestVectors {
    /* tests for HelixEncryption#HelixEncryption(byte[], byte[]) */

    /**
     * Asserts that {@link HelixEncryption#HelixEncryption(byte[], byte[])}
     * succeeds with a valid key and nonce.
     * 
     * <p>
     * This method exists so that the {@link HelixEncryption} constructor is
     * exercised. Refer to {@link HelixImplTest} for more exhaustive tests of
     * the {@link HelixPrimitive} constructor.
     * </p>
     */
    @Test
    public void initAcceptsKeyAndNonce() {
        @SuppressWarnings("unused")
        HelixPrimitive primitive = new HelixEncryption(new byte[32], new byte[16]);
    }

    /* tests for HelixEncryption#feed(byte[]) and HelixEncryption#finish(byte[]) */

    /**
     * Asserts that {@link HelixEncryption} produces the expected ciphertext and
     * MAC when Helix test vector #1 plaintext is fed incrementally.
     */
    @Test
    public void encryptByFeeding1() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE]);
        ByteBuffer actualCipherText = ByteBuffer.allocate(TEST_VECTOR_1[CIPHERTEXT].length);

        byte[] plainTextPart = new byte[3];
        System.arraycopy(TEST_VECTOR_1[PLAINTEXT], 0, plainTextPart, 0, 3);
        primitive.feed(plainTextPart);

        System.arraycopy(TEST_VECTOR_1[PLAINTEXT], 3, plainTextPart, 0, 3);
        actualCipherText.put(primitive.feed(plainTextPart));

        System.arraycopy(TEST_VECTOR_1[PLAINTEXT], 6, plainTextPart, 0, 3);
        actualCipherText.put(primitive.feed(plainTextPart));

        plainTextPart = new byte[1];
        System.arraycopy(TEST_VECTOR_1[PLAINTEXT], 9, plainTextPart, 0, 1);
        actualCipherText.put(primitive.finish(plainTextPart));

        assertArrayEquals(TEST_VECTOR_1[CIPHERTEXT], actualCipherText.array());
        assertArrayEquals(TEST_VECTOR_1[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixEncryption} produces the expected ciphertext and
     * MAC when Helix test vector #2 plaintext is fed incrementally.
     */
    @Test
    public void encryptByFeeding2() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE]);
        ByteBuffer actualCipherText = ByteBuffer.allocate(TEST_VECTOR_2[CIPHERTEXT].length);

        byte[] plainTextPart = new byte[5];
        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 0, plainTextPart, 0, 5);
        actualCipherText.put(primitive.feed(plainTextPart));

        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 5, plainTextPart, 0, 5);
        actualCipherText.put(primitive.feed(plainTextPart));

        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 10, plainTextPart, 0, 5);
        actualCipherText.put(primitive.feed(plainTextPart));

        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 15, plainTextPart, 0, 5);
        actualCipherText.put(primitive.feed(plainTextPart));

        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 20, plainTextPart, 0, 5);
        actualCipherText.put(primitive.feed(plainTextPart));

        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 25, plainTextPart, 0, 5);
        actualCipherText.put(primitive.feed(plainTextPart));

        plainTextPart = new byte[2];
        System.arraycopy(TEST_VECTOR_2[PLAINTEXT], 30, plainTextPart, 0, 2);
        actualCipherText.put(primitive.finish(plainTextPart));

        assertArrayEquals(TEST_VECTOR_2[CIPHERTEXT], actualCipherText.array());
        assertArrayEquals(TEST_VECTOR_2[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixEncryption} produces the expected ciphertext and
     * MAC when Helix test vector #3 plaintext is fed incrementally.
     */
    @Test
    public void encryptByFeeding3() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE]);
        ByteBuffer actualCipherText = ByteBuffer.allocate(TEST_VECTOR_3[CIPHERTEXT].length);

        byte[] plainTextPart = new byte[7];
        System.arraycopy(TEST_VECTOR_3[PLAINTEXT], 0, plainTextPart, 0, 7);
        actualCipherText.put(primitive.feed(plainTextPart));

        plainTextPart = new byte[6];
        System.arraycopy(TEST_VECTOR_3[PLAINTEXT], 7, plainTextPart, 0, 6);
        actualCipherText.put(primitive.feed(plainTextPart));

        actualCipherText.put(primitive.finish(new byte[0]));

        assertArrayEquals(TEST_VECTOR_3[CIPHERTEXT], actualCipherText.array());
        assertArrayEquals(TEST_VECTOR_3[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixEncryption} produces the expected ciphertext and
     * MAC when Helix test vector #1 plaintext is passed in whole to
     * {@link HelixEncryption#finish(byte[])}.
     */
    @Test
    public void encryptAtOnceUsingFinish1() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE]);
        byte[] actualCipherText = primitive.finish(TEST_VECTOR_1[PLAINTEXT]);

        assertArrayEquals(TEST_VECTOR_1[CIPHERTEXT], actualCipherText);
        assertArrayEquals(TEST_VECTOR_1[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixEncryption} produces the expected ciphertext and
     * MAC when Helix test vector #1 plaintext is passed in whole to
     * {@link HelixEncryption#finish(byte[])}.
     */
    @Test
    public void encryptAtOnceUsingFinish2() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_2[KEY], TEST_VECTOR_2[NONCE]);
        byte[] actualCipherText = primitive.finish(TEST_VECTOR_2[PLAINTEXT]);

        assertArrayEquals(TEST_VECTOR_2[CIPHERTEXT], actualCipherText);
        assertArrayEquals(TEST_VECTOR_2[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixEncryption} produces the expected ciphertext and
     * MAC when Helix test vector #1 plaintext is passed in whole to
     * {@link HelixEncryption#finish(byte[])}.
     */
    @Test
    public void encryptAtOnceUsingFinish3() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_3[KEY], TEST_VECTOR_3[NONCE]);
        byte[] actualCipherText = primitive.finish(TEST_VECTOR_3[PLAINTEXT]);

        assertArrayEquals(TEST_VECTOR_3[CIPHERTEXT], actualCipherText);
        assertArrayEquals(TEST_VECTOR_3[MAC], primitive.getGeneratedMac());
    }

    /**
     * Asserts that {@link HelixEncryption#getGeneratedMac()} fails if called
     * before the encryption operation has completed.
     */
    @Test(expected = IllegalStateException.class)
    public void getGeneratedMacFailsBeforeEncryptOperationHasCompleted() {
        HelixEncryption primitive = new HelixEncryption(TEST_VECTOR_1[KEY], TEST_VECTOR_1[NONCE]);

        byte[] plainTextPart = new byte[3];
        System.arraycopy(TEST_VECTOR_1[PLAINTEXT], 0, plainTextPart, 0, 3);
        primitive.feed(plainTextPart);

        @SuppressWarnings("unused")
        byte[] mac = primitive.getGeneratedMac();
    }
}
