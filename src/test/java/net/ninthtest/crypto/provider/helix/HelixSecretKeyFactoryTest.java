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
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import net.ninthtest.security.provider.NinthTestProvider;
import org.junit.Before;
import org.junit.Test;

/**
 * The unit test case for {@link HelixSecretKeyFactory}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixSecretKeyFactoryTest {
    /* The instance used by unit tests. */
    private HelixSecretKeyFactory factory;

    /**
     * Creates a {@link HelixSecretKeyFactory} instance for testing.
     */
    @Before
    public void createHelixSecretKeyFactory() {
        factory = new HelixSecretKeyFactory();
    }

    /* tests for HelixSecretKeyFactory#engineGenerateSecret(KeySpec) */

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineGenerateSecret(KeySpec)}
     * rejects a <tt>null</tt> {@link KeySpec} argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGenerateSecretRejectsNullKeySpec() throws InvalidKeySpecException {
        factory.engineGenerateSecret(null);
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineGenerateSecret(KeySpec)}
     * rejects a non-{@link HelixKeySpec} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGenerateSecretRejectsNonHelixKeySpec() throws InvalidKeyException, InvalidKeySpecException {
        KeySpec desSpec = new DESKeySpec(new byte[8]);

        factory.engineGenerateSecret(desSpec);
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineGenerateSecret(KeySpec)}
     * accepts a {@link HelixKeySpec} argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test fails
     */
    @Test
    public void engineGenerateSecretAcceptsHelixKeySpec() throws InvalidKeySpecException {
        HelixKeySpec keySpec = new HelixKeySpec(new byte[32]);
        factory.engineGenerateSecret(keySpec);
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineGenerateSecret(KeySpec)}
     * generates a Helix secret key.
     * 
     * @throws InvalidKeySpecException
     *             if the test fails
     */
    @Test
    public void engineGenerateSecretHelixKey() throws InvalidKeySpecException {
        HelixKeySpec keySpec = new HelixKeySpec(new byte[32]);
        SecretKey key = factory.engineGenerateSecret(keySpec);

        assertEquals(NinthTestProvider.HELIX, key.getAlgorithm());
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineGenerateSecret(KeySpec)}
     * generates <i>RAW</i>-format secret keys.
     * 
     * @throws InvalidKeySpecException
     *             if the test fails
     */
    @Test
    public void engineGenerateSecretRAWFormat() throws InvalidKeySpecException {
        HelixKeySpec keySpec = new HelixKeySpec(new byte[32]);
        SecretKey key = factory.engineGenerateSecret(keySpec);

        assertEquals("RAW", key.getFormat());
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineGenerateSecret(KeySpec)}
     * generates the expected secret key bytes.
     * 
     * @throws InvalidKeySpecException
     *             if the test fails
     */
    @Test
    public void engineGenerateSecretExpectedKeyBytes() throws InvalidKeySpecException {
        byte[] material = new byte[32];
        material[0] = (byte) 1;
        material[8] = (byte) 2;
        material[16] = (byte) 3;
        material[24] = (byte) 4;
        HelixKeySpec keySpec = new HelixKeySpec(material);
        SecretKey key = factory.engineGenerateSecret(keySpec);

        assertArrayEquals(material, key.getEncoded());
    }

    /* tests for HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class) */

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} rejects
     * a <tt>null</tt> {@link SecretKey} argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGetKeySpecRejectsNullSecretKey() throws InvalidKeySpecException {
        factory.engineGetKeySpec(null, HelixKeySpec.class);
    }

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} rejects
     * a non-Helix {@link SecretKey} argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGetKeySpecRejectsNonHelixSecretKey() throws InvalidKeySpecException {
        SecretKey notHelix = new SecretKeySpec(new byte[24], "DESede");

        factory.engineGetKeySpec(notHelix, HelixKeySpec.class);
    }

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} rejects
     * a non-<i>RAW</i>-format {@link SecretKey} argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGetKeySpecRejectsNonRAWSecretKey() throws InvalidKeySpecException {
        @SuppressWarnings("serial")
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX) {
            @Override
            public String getFormat() {
                return "NotRAW";
            }
        };

        factory.engineGetKeySpec(secret, HelixKeySpec.class);
    }

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} rejects
     * a <tt>null</tt> class argument}.
     * 
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGetKeySpecRejectsNullClass() throws InvalidKeySpecException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);

        factory.engineGetKeySpec(secret, null);
    }

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} rejects
     * a non-{@link HelixKeySpec} class argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeySpecException.class)
    public void engineGetKeySpecRejectsNonHelixClass() throws InvalidKeySpecException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        factory.engineGetKeySpec(secret, DESKeySpec.class);
    }

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} accepts
     * a {@link HelixKeySpec} class argument.
     * 
     * @throws InvalidKeySpecException
     *             if the test fails
     */
    @Test
    public void engineGetKeySpecAcceptsHelixClass() throws InvalidKeySpecException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        KeySpec actualKeySpec = factory.engineGetKeySpec(secret, HelixKeySpec.class);
        assertTrue(actualKeySpec instanceof HelixKeySpec);
    }

    /**
     * Asserts that
     * {@link HelixSecretKeyFactory#engineGetKeySpec(SecretKey, Class)} produces
     * the expected {@link HelixKeySpec} object.
     * 
     * @throws InvalidKeySpecException
     *             if the test fails
     */
    @Test
    public void engineGetKeySpecExpectedHelixObject() throws InvalidKeySpecException {
        byte[] material = new byte[32];
        material[0] = (byte) 1;
        material[8] = (byte) 2;
        material[16] = (byte) 3;
        material[24] = (byte) 4;
        SecretKey secret = new SecretKeySpec(material, NinthTestProvider.HELIX);
        HelixKeySpec spec = (HelixKeySpec) factory.engineGetKeySpec(secret, HelixKeySpec.class);

        assertArrayEquals(material, spec.getKey());
    }

    /* tests for HelixSecretKeyFactory#engineTranslateKey(SecretKey) */

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineTranslateKey(SecretKey)}
     * rejects a <tt>null</tt> {@link SecretKey} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineTranslateKeyRejectsNullSecretKey() throws InvalidKeyException {
        factory.engineTranslateKey(null);
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineTranslateKey(SecretKey)}
     * successfully translates a secret key of less than 32 bytes.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test
    public void engineTranslateKeyLT32Bytes() throws InvalidKeyException {
        SecretKey desSecret = new SecretKeySpec(new byte[8], "DES");
        SecretKey helixSecret = factory.engineTranslateKey(desSecret);

        assertArrayEquals(desSecret.getEncoded(), helixSecret.getEncoded());
    }

    /**
     * Asserts that {@link HelixSecretKeyFactory#engineTranslateKey(SecretKey)}
     * successfully translates a secret key of greater than 32 bytes.
     * 
     * @throws NoSuchAlgorithmException
     *             if the test fails
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test
    public void engineTranslateKeyGT32Bytes() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyGenerator generator = KeyGenerator.getInstance("Blowfish");
        generator.init(448); // max Blowfish key size in bits
        SecretKey blowfishSecret = generator.generateKey();
        byte[] blowfishFirst256 = new byte[32];
        System.arraycopy(blowfishSecret.getEncoded(), 0, blowfishFirst256, 0, 32);
        SecretKey helixSecret = factory.engineTranslateKey(blowfishSecret);

        assertArrayEquals(blowfishFirst256, helixSecret.getEncoded());
    }
}
