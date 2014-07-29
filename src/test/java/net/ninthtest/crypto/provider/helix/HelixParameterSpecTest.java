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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.junit.Test;

/**
 * The unit test case for {@link HelixParameterSpec}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixParameterSpecTest {
    /* tests for HelixParameterSpec#HelixParameterSpec(byte[]) */

    /**
     * Asserts that {@link HelixParameterSpec#HelixParameterSpec(byte[])}
     * rejects a <tt>null</tt> nonce argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNullNonce() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(null);
    }

    /**
     * Asserts that {@link HelixParameterSpec#HelixParameterSpec(byte[])}
     * rejects a nonce that is less than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNonceLT16Bytes() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[15]);
    }

    /**
     * Asserts that {@link HelixParameterSpec#HelixParameterSpec(byte[])}
     * rejects a nonce that is longer than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNonceGT16Bytes() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[17]);
    }

    /**
     * Asserts that {@link HelixParameterSpec#HelixParameterSpec(byte[])}
     * accepts a 16-byte nonce.
     */
    @Test
    public void initAccepts16ByteNonce() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
    }

    /**
     * Asserts that {@link HelixParameterSpec#HelixParameterSpec(byte[])} copies
     * the nonce bytes so that they cannot be modified by reference.
     */
    @Test
    public void initCopiesNonceBytes() {
        byte[] nonce = new byte[16];
        HelixParameterSpec spec = new HelixParameterSpec(nonce);
        nonce[0] = (byte) 1;

        assertFalse(Arrays.equals(nonce, spec.getNonce()));
    }

    /* tests for HelixParameterSpec#HelixParameterSpec(byte[], byte[]) */

    /**
     * Asserts that
     * {@link HelixParameterSpec#HelixParameterSpec(byte[], byte[])} rejects a
     * <tt>null</tt> MAC argument.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsNullMac() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[16], null);
    }

    /**
     * Asserts that
     * {@link HelixParameterSpec#HelixParameterSpec(byte[], byte[])} rejects a
     * MAC that is less than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsMacLT16Bytes() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[16], new byte[15]);
    }

    /**
     * Asserts that
     * {@link HelixParameterSpec#HelixParameterSpec(byte[], byte[])} rejects a
     * MAC that is longer than 16 bytes.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initRejectsMacGT16Bytes() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[16], new byte[17]);
    }

    /**
     * Asserts that
     * {@link HelixParameterSpec#HelixParameterSpec(byte[], byte[])} accepts a
     * 16-byte MAC.
     */
    @Test
    public void initAccepts16ByteMac() {
        @SuppressWarnings("unused")
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(new byte[16], new byte[16]);
    }

    /**
     * Asserts that
     * {@link HelixParameterSpec#HelixParameterSpec(byte[], byte[])} copies the
     * MAC bytes so that they cannot be modified by reference.
     */
    @Test
    public void initCopiesMacBytes() {
        byte[] mac = new byte[16];
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16], mac);
        mac[0] = (byte) 1;

        assertFalse(Arrays.equals(mac, spec.getMac()));
    }

    /* tests for HelixParameterSpec#getNonce() */

    /**
     * Asserts that {@link HelixParameterSpec#getNonce()} returns a copy of the
     * nonce bytes so that they cannot be modified by reference.
     */
    @Test
    public void getNonceCopiesBytes() {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16]);
        byte[] nonce = spec.getNonce();
        nonce[0] = (byte) 1;

        assertFalse(Arrays.equals(nonce, spec.getNonce()));
    }

    /* tests for HelixParameterSpec#getMac() */

    /**
     * Asserts that {@link HelixParameterSpec#getMac()} returns <tt>null</tt> if
     * the parameter specification was not initialized with an expected MAC.
     */
    @Test
    public void getMacReturnsNull() {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16]);

        assertNull(spec.getMac());
    }

    /**
     * Asserts that {@link HelixParameterSpec#getMac()} returns a copy of the
     * MAC bytes so that they cannot be modified by reference.
     */
    @Test
    public void getMacCopiesBytes() {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16], new byte[16]);
        byte[] mac = spec.getMac();
        mac[0] = (byte) 1;

        assertFalse(Arrays.equals(mac, spec.getMac()));
    }
}
