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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.security.spec.KeySpec;
import java.util.Arrays;

import org.junit.Test;

/**
 * The unit test case for {@link HelixKeySpec}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixKeySpecTest {
    /* tests for HelixKeySpec#HelixKeySpec(byte[])} */

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} rejects a
     * <tt>null</tt> argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNullByteArray() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(null);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} rejects a
     * zero-length byte array argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsZeroLengthByteArray() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[0]);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} accepts a byte
     * array that is less than 32 bytes in length.
     */
    @Test
    public void initAcceptsByteArrayLT32() {
        // length of key material is < 32 bytes
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[1]);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} accepts a byte
     * array that is exactly 32 bytes in length.
     */
    @Test
    public void initAcceptsByteArrayEQ32() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[32]);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} accepts a byte
     * array that is greater than 32 bytes in length.
     */
    @Test
    public void initAcceptsByteArrayGT32() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[64]);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} only uses the
     * first 32 bytes of the key material.
     */
    @Test
    public void initOnlyUsesFirst32Bytes() {
        byte[] material = new byte[33];
        material[32] = (byte) 1;
        HelixKeySpec spec = new HelixKeySpec(material);

        assertArrayEquals(new byte[32], spec.getKey());
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[])} makes a copy of
     * the byte array argument so that the array content cannot be modified by
     * reference.
     */
    @Test
    public void initByteArrayCannotBeModified() {
        byte[] keyMaterial = new byte[32];
        HelixKeySpec spec = new HelixKeySpec(keyMaterial);
        keyMaterial[0] = (byte) 1;

        assertFalse(Arrays.equals(keyMaterial, spec.getKey()));
    }

    /* tests for HelixKeySpec#HelixKeySpec(byte[], int) */

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[], int)} fails if the
     * offset is less than zero.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initOffsetLTZero() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[32], -1);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[], int)} fails if the
     * offset is equal to the byte array length.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initOffsetEqualsLength() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[32], 32);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[], int)} fails if the
     * offset is greater than the byte array length.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initOffsetExceedsLength() {
        @SuppressWarnings("unused")
        KeySpec keySpec = new HelixKeySpec(new byte[32], 33);
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[], int)} uses less
     * than 32 bytes when (length - offset) is less than 32 bytes.
     */
    @Test
    public void initUsesLessThan32Bytes() {
        byte[] material = new byte[40];
        material[15] = (byte) 1;
        HelixKeySpec spec = new HelixKeySpec(material, 16);

        assertArrayEquals(new byte[24], spec.getKey());
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[], int)} uses only 32
     * bytes when (length - offset) is greater than 32 bytes.
     */
    @Test
    public void initOnlyUses32Bytes() {
        byte[] material = new byte[40];
        material[3] = (byte) 1;
        material[36] = (byte) 1;
        HelixKeySpec spec = new HelixKeySpec(material, 4);

        assertArrayEquals(new byte[32], spec.getKey());
    }

    /**
     * Asserts that {@link HelixKeySpec#HelixKeySpec(byte[], int)} makes a copy
     * of the byte array argument so that the array content cannot be modified
     * by reference.
     */
    @Test
    public void initByteArrayWithOffsetCannotBeModified() {
        byte[] keyMaterial = new byte[32];
        HelixKeySpec spec = new HelixKeySpec(keyMaterial, 0);
        keyMaterial[0] = (byte) 1;

        assertFalse(Arrays.equals(keyMaterial, spec.getKey()));
    }

    /* tests for HelixKeySpec#getKey() */

    /**
     * Asserts that {@link HelixKeySpec#getKey()} makes a copy of the key
     * material byte array so that the array content cannot be modified by
     * reference.
     */
    @Test
    public void getKeyCannotBeModified() {
        HelixKeySpec spec = new HelixKeySpec(new byte[32]);
        byte[] keyMaterial = spec.getKey();
        keyMaterial[0] = (byte) 1;

        assertFalse(Arrays.equals(keyMaterial, spec.getKey()));
    }
}
