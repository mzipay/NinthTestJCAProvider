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
import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;

/**
 * The unit test case for {@link HelixSecureRandom}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixSecureRandomTest {
    /* The instance used by unit tests. */
    private HelixSecureRandom secureRandomSpi;

    /**
     * Creates a {@link HelixSecureRandom} instance for testing.
     */
    @Before
    public void createHelixSecureRandom() {
        secureRandomSpi = new HelixSecureRandom();
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineSetSeed(byte[])} rejects a
     * <tt>null</tt> argument.
     * 
     * @throws IllegalArgumentException
     *             if the test succeeds
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineSetSeedRejectsNullSeed() {
        secureRandomSpi.engineSetSeed(null);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineSetSeed(byte[])} accepts an
     * empty byte array as the seed.
     * <p>
     * (In this case, the internal seeding mechanism will be used.)
     * </p>
     */
    @Test
    public void engineSetSeedAcceptsEmptyArray() {
        secureRandomSpi.engineSetSeed(new byte[0]);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineSetSeed(byte[])} accepts a
     * byte array that is shorter than the internal seed state.
     */
    @Test
    public void engineSetSeedAcceptsSmallArray() {
        byte[] small = new byte[29];
        (new SecureRandom()).nextBytes(small);
        secureRandomSpi.engineSetSeed(small);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineSetSeed(byte[])} accepts a
     * byte array that is longer than the internal seed state.
     */
    @Test
    public void engineSetSeedAcceptsLargeArray() {
        byte[] large = new byte[79];
        (new SecureRandom()).nextBytes(large);
        secureRandomSpi.engineSetSeed(large);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineSetSeed(byte[])}
     * reinitializes the internal Helix primitive when called on an
     * already-initialized instance.
     */
    @Test
    public void engineSetSeedReinitializesHelixPrimitive() {
        byte[] request1 = new byte[8];
        secureRandomSpi.engineNextBytes(request1);

        byte[] newSeed = new byte[48];
        (new SecureRandom()).nextBytes(newSeed);
        secureRandomSpi.engineSetSeed(newSeed);

        byte[] request2 = new byte[8];
        secureRandomSpi.engineNextBytes(request2);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineNextBytes(byte[])} rejects a
     * <tt>null</tt> argument.
     * 
     * @throws IllegalArgumentException
     *             if the test succeeds
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineNextBytesRejectsNullArray() {
        secureRandomSpi.engineNextBytes(null);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineNextBytes(byte[])} is a no-op
     * if the bytes array argument is emtpy.
     */
    @Test
    public void engineNextBytesNoOpIfEmptyArray() {
        secureRandomSpi.engineNextBytes(new byte[0]);
    }

    /**
     * Asserts that a call to {@link HelixSecureRandom#engineNextBytes(byte[])}
     * initializes the PRNG if {@link HelixSecureRandom#engineSetSeed(byte[])}
     * has not been called explicitly.
     */
    @Test
    public void engineNextBytesInitializesSelf() {
        byte[] test = new byte[32];
        secureRandomSpi.engineNextBytes(test);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineNextBytes(byte[])} uses the
     * already-initialized PRNG if
     * {@link HelixSecureRandom#engineSetSeed(byte[])} has already been called
     * explicitly.
     */
    @Test
    public void engineNextBytesAlreadyInitialized() {
        byte[] seed = new byte[48];
        (new SecureRandom()).nextBytes(seed);
        secureRandomSpi.engineSetSeed(seed);

        byte[] test = new byte[32];
        secureRandomSpi.engineNextBytes(test);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineNextBytes(byte[])} buffers
     * any "extra" bytes (up to seven) when fulfilling a request.
     */
    @Test
    public void engineNextBytesBuffersExtra() {
        byte[] request = new byte[1]; // 7 bytes will be buffered
        secureRandomSpi.engineNextBytes(request);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineNextBytes(byte[])} can
     * satisfy a sufficiently small request from buffered bytes.
     */
    @Test
    public void engineNextBytesFulfillUsingBuffer() {
        byte[] request1 = new byte[1]; // 7 bytes will be buffered
        secureRandomSpi.engineNextBytes(request1);
        byte[] request2 = new byte[5];
        secureRandomSpi.engineNextBytes(request2); // fulfilled from buffer
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineNextBytes(byte[])} can
     * consume all remaining bytes from the internal buffer.
     */
    @Test
    public void engineNextBytesConsumesBuffer() {
        byte[] request1 = new byte[1]; // 7 bytes will be buffered
        secureRandomSpi.engineNextBytes(request1);
        byte[] request2 = new byte[7];
        secureRandomSpi.engineNextBytes(request2); // empties the buffer
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineGenerateSeed(int)} rejects a
     * negative argument.
     * 
     * @throws IllegalArgumentException
     *             if the test succeeds
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineGenerateSeedRejectsNegative() {
        secureRandomSpi.engineGenerateSeed(-1);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineGenerateSeed(int)} is a no-op
     * if the size argument is zero.
     */
    @Test
    public void engineGenerateSeedNoOpIfZeroSize() {
        byte[] seed = secureRandomSpi.engineGenerateSeed(0);

        assertArrayEquals(new byte[0], seed);
    }

    /**
     * Asserts that {@link HelixSecureRandom#engineGenerateSeed(int)} produces
     * the expected-size seed value.
     */
    @Test
    public void engineGenerateSeedPositiveNonZeroSize() {
        byte[] seed = secureRandomSpi.engineGenerateSeed(32);

        assertEquals(32, seed.length);
    }
}
