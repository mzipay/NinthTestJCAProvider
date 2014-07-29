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

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

/**
 * The unit test case for {@link HelixKeyGenerator}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixKeyGeneratorTest {
    /* the instance used by test fixtures */
    private HelixKeyGenerator generator;

    /**
     * Creates a {@link HelixKeyGenerator} instance for testing.
     */
    @Before
    public void createHelixKeyGenerator() {
        // defaults: 256-bit key size, platform default RNG
        generator = new HelixKeyGenerator();
    }

    /* tests for HelixKeyGenerator#engineInit(SecureRandom) */

    /**
     * Asserts that {@link HelixKeyGenerator#engineInit(SecureRandom)} accepts a
     * default {@link SecureRandom} argument.
     */
    @Test
    public void engineInitAcceptsDefaultSecureRandom() {
        generator.engineInit(new SecureRandom());
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineInit(SecureRandom)} accepts a
     * non-default {@link SecureRandom} argument.
     * 
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsNonDefaultSecureRandom() throws NoSuchAlgorithmException {
        generator.engineInit(SecureRandom.getInstance("SHA1PRNG"));
    }

    /* tests for HelixKeyGenerator#engineInit(int, SecureRandom) */

    /**
     * Asserts that {@link HelixKeyGenerator#engineInit(int, SecureRandom)}
     * rejects a key size that exceeds the maximum allowed key size (256 bits).
     */
    @Test(expected = InvalidParameterException.class)
    public void engineInitRejectsKeySizeGT256() {
        generator.engineInit(264, new SecureRandom());
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineInit(int, SecureRandom)}
     * rejects a key size that exceeds the maximum allowed key size (256 bits).
     */
    @Test(expected = InvalidParameterException.class)
    public void engineInitRejectsKeySizeNonMultipleOfEight() {
        generator.engineInit(129, new SecureRandom());
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineInit(int, SecureRandom)}
     * accepts a valid key size and a default {@link SecureRandom} argument.
     */
    @Test
    public void engineInitAcceptsKeySizeAndDefaultSecureRandom() {
        generator.engineInit(192, new SecureRandom());
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineInit(int, SecureRandom)}
     * accepts a valid key size and a non-default {@link SecureRandom} argument.
     * 
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsKeySizeAndNonDefaultSecureRandom() throws NoSuchAlgorithmException {
        generator.engineInit(64, SecureRandom.getInstance("SHA1PRNG"));
    }

    /*
     * tests for HelixKeyGenerator#engineInit(AlgorithmParameterSpec,
     * SecureRandom)
     */

    /**
     * Asserts that
     * {@link HelixKeyGenerator#engineInit(AlgorithmParameterSpec, SecureRandom)}
     * throws an exception.
     * 
     * <p>
     * The Helix key generator does not support algorithm parameters.
     * </p>
     * 
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitRejectsAlgorithmParameterSpec() throws InvalidAlgorithmParameterException {
        generator.engineInit(new AlgorithmParameterSpec() {
            /* no-op for testing */
        }, new SecureRandom());
    }

    /* tests for HelixKeyGenerator#engineGenerateKey() */

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} generates
     * Helix secret keys.
     */
    @Test
    public void engineGenerateKeyForHelixAlgorithm() {
        SecretKey secret = generator.engineGenerateKey();

        assertEquals("Helix", secret.getAlgorithm());
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} generates
     * secret keys in <i>RAW</i> format.
     */
    @Test
    public void engineGenerateKeyInRAWFormat() {
        SecretKey secret = generator.engineGenerateKey();

        assertEquals("RAW", secret.getFormat());
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} uses a default
     * key size of 256 bits (32 bytes).
     */
    @Test
    public void engineGenerateKeyDefault256Bits() {
        SecretKey secret = generator.engineGenerateKey();

        assertEquals(32, secret.getEncoded().length);
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} can generate a
     * 128-bit key.
     */
    @Test
    public void engineGenerateKey128Bits() {
        generator.engineInit(128, new SecureRandom());
        SecretKey secret = generator.engineGenerateKey();

        assertEquals(16, secret.getEncoded().length);
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} can generate a
     * 192-bit key.
     */
    @Test
    public void engineGenerateKey192Bits() {
        generator.engineInit(192, new SecureRandom());
        SecretKey secret = generator.engineGenerateKey();

        assertEquals(24, secret.getEncoded().length);
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} can generate a
     * 256-bit key.
     */
    @Test
    public void engineGenerateKey256Bits() {
        generator.engineInit(256, new SecureRandom());
        SecretKey secret = generator.engineGenerateKey();

        assertEquals(32, secret.getEncoded().length);
    }

    /**
     * Asserts that {@link HelixKeyGenerator#engineGenerateKey()} can generate
     * any non-standard key size that is a multiple of eight and less than 256
     * (bits).
     */
    @Test
    public void engineGenerateKeyNonStandardSizes() {
        SecretKey secret = null;
        for (int i = 8; i <= 256; i += 8) {
            generator.engineInit(i, new SecureRandom());
            secret = generator.engineGenerateKey();

            assertEquals(i / 8, secret.getEncoded().length);
        }
    }
}
