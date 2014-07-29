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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.ninthtest.crypto.helix.HelixTestVectors;
import net.ninthtest.security.provider.NinthTestProvider;
import org.junit.Before;
import org.junit.Test;

/**
 * The unit test case for {@link HelixMac}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixMacTest implements HelixTestVectors {
    /* The instance used by unit tests. */
    private HelixMac macSpi;

    /**
     * Creates a {@link HelixMac} instance for testing.
     */
    @Before
    public void createHelixMac() {
        macSpi = new HelixMac();
    }

    /**
     * Asserts that {@link HelixMac#engineGetMacLength()} returns <tt>16</tt>.
     */
    @Test
    public void testEngineGetMacLength() {
        assertEquals(16, macSpi.engineGetMacLength());
    }

    /*
     * tests for HelixMac#engineInit(java.security.Key,
     * java.security.spec.AlgorithmParameterSpec)
     */

    /**
     * Asserts that
     * {@link HelixMac#engineInit(java.security.Key, java.security.spec.AlgorithmParameterSpec)}
     * rejects a <tt>null</tt> {@link java.security.Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitRejectsNullKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        macSpi.engineInit(null, new HelixParameterSpec(new byte[16]));
    }

    /**
     * Asserts that
     * {@link HelixMac#engineInit(java.security.Key, java.security.spec.AlgorithmParameterSpec)}
     * rejects a non-Helix {@link java.security.Key} argument.
     * 
     * @throws NoSuchAlgorithmException
     *             if the test fails
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitRejectsNonHelixKey() throws NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        KeyGenerator generator = KeyGenerator.getInstance("Blowfish");
        generator.init(256);
        SecretKey blowfishSecret = generator.generateKey();

        macSpi.engineInit(blowfishSecret, new HelixParameterSpec(new byte[16]));
    }

    /**
     * Asserts that
     * {@link HelixMac#engineInit(java.security.Key, java.security.spec.AlgorithmParameterSpec)}
     * rejects a non-{@link SecretKey} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitRejectsNonSecretKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        @SuppressWarnings("serial")
        PublicKey publicKey = new PublicKey() {
            @Override
            public String getAlgorithm() {
                /*
                 * to avoid a false-positive outcome - see
                 * #engineInitRejectsNonHelixKey()
                 */
                return NinthTestProvider.HELIX;
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }

            @Override
            public String getFormat() {
                return null;
            }
        };

        macSpi.engineInit(publicKey, new HelixParameterSpec(new byte[16]));
    }

    /**
     * Asserts that
     * {@link HelixMac#engineInit(java.security.Key, java.security.spec.AlgorithmParameterSpec)}
     * rejects a <tt>null</tt> {@link java.security.spec.AlgorithmParameterSpec}
     * argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitRejectsNullSpec() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);

        macSpi.engineInit(secret, null);
    }

    /**
     * Asserts that
     * {@link HelixMac#engineInit(java.security.Key, java.security.spec.AlgorithmParameterSpec)}
     * rejects a non-Helix {@link java.security.spec.AlgorithmParameterSpec}
     * argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitRejectsNonHelixSpec() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);

        macSpi.engineInit(secret, ivSpec);
    }

    /**
     * Asserts that
     * {@link HelixMac#engineInit(java.security.Key, java.security.spec.AlgorithmParameterSpec)}
     * accepts a Helix secret key and algorithm parameter specification.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsHelixKeyAndSpec() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);

        macSpi.engineInit(secret, paramSpec);
    }

    /* tests for HelixMac#engineUpdate(byte) */

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte)} can feed a single byte
     * of input to the Helix encryption primitive.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineUpdateSingleByte() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate((byte) 0);
    }

    /* tests for HelixMac#engineUpdate(byte[], int, int) */

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} rejects a
     * <tt>null</tt> byte array argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateRejectsNullByteArray() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(null, 0, 4);
    }

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} fails if the
     * offset is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateOffsetLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(new byte[4], -1, 4);
    }

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} fails if the
     * offset is equal to the input byte array length.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateOffsetEQByteArrayLength() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(new byte[4], 4, 4);
    }

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} fails if the
     * offset exceeds the input byte array length.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateOffsetExceedsByteArrayLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(new byte[4], 5, 4);
    }

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} fails if the
     * length is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateLengthLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(new byte[4], 0, -1);
    }

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} fails if the
     * length exceeds the bytes available from the input array beginning at the
     * offset.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateLengthExceedsAvailable() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(new byte[4], 0, 5);
    }

    /**
     * Asserts that {@link HelixMac#engineUpdate(byte[], int, int)} can feed a
     * range of input bytes to the Helix encryption primitive.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineUpdateRangeOfBytes() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(new byte[32], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(new byte[16]);
        macSpi.engineInit(secret, paramSpec);

        macSpi.engineUpdate(new byte[64], 16, 32);
    }

    /*
     * tests for HelixMac#engineDoFinal() (NOTE: Helix test vector #1 cannot be
     * used because SecretKeyFactory will not accept zero-byte key material)
     */

    /**
     * Asserts that {@link HelixMac#engineDoFinal()} produces the expected MAC
     * for Helix test vector #2.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineDoFinal2() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(TEST_VECTOR_2[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_2[NONCE]);
        macSpi.engineInit(secret, paramSpec);
        macSpi.engineUpdate(TEST_VECTOR_2[PLAINTEXT], 0, TEST_VECTOR_2[PLAINTEXT].length);
        byte[] mac = macSpi.engineDoFinal();

        assertArrayEquals(TEST_VECTOR_2[MAC], mac);
    }

    /**
     * Asserts that {@link HelixMac#engineDoFinal()} produces the expected MAC
     * for Helix test vector #3.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineDoFinal3() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(TEST_VECTOR_3[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        macSpi.engineInit(secret, paramSpec);
        macSpi.engineUpdate(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);
        byte[] mac = macSpi.engineDoFinal();

        assertArrayEquals(TEST_VECTOR_3[MAC], mac);
    }

    /* tests for HelixMac#engineReset() */

    /**
     * Asserts that a {@link HelixMac} can be re-used after a MAC is generated.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void reusableAfterDoFinal() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(TEST_VECTOR_2[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_2[NONCE]);
        macSpi.engineInit(secret, paramSpec);
        macSpi.engineUpdate(TEST_VECTOR_2[PLAINTEXT], 0, TEST_VECTOR_2[PLAINTEXT].length);
        macSpi.engineDoFinal();

        // would otherwise throw IllegalStateException
        macSpi.engineUpdate(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);
    }

    /**
     * Asserts that {@link HelixMac#engineReset()} re-initializes the Helix MAC
     * generator so that the same instance can be used again.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void reusableAfterReset() throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKey secret = new SecretKeySpec(TEST_VECTOR_2[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_2[NONCE]);
        macSpi.engineInit(secret, paramSpec);
        macSpi.engineUpdate(TEST_VECTOR_2[PLAINTEXT], 0, TEST_VECTOR_2[PLAINTEXT].length);

        macSpi.engineReset();

        secret = new SecretKeySpec(TEST_VECTOR_3[KEY], NinthTestProvider.HELIX);
        paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        macSpi.engineInit(secret, paramSpec);
        macSpi.engineUpdate(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);
        byte[] mac = macSpi.engineDoFinal();

        assertArrayEquals(TEST_VECTOR_3[MAC], mac);
    }
}
