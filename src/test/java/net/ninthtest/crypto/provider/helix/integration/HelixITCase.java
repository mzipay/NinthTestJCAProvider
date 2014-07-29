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

package net.ninthtest.crypto.provider.helix.integration;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import net.ninthtest.crypto.provider.helix.HelixKeySpec;
import net.ninthtest.crypto.provider.helix.HelixParameterSpec;
import net.ninthtest.security.provider.NinthTestProvider;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * The integration test case for {@link NinthTestProvider} Helix services.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixITCase {
    /** The plaintext phrase used for testing. */
    public static final String PLAINTEXT_STRING = "The quick brown fox jumps over the lazy dog.";

    /**
     * Dynamically registers the "NinthTest" security provider if the
     * "ninthtest.provider.register" system property is <i>true</i>.
     */
    @BeforeClass
    public static void dynamicRegistration() {
        if (Boolean.getBoolean("ninthtest.provider.register")) {
            int preference = Security.addProvider(new NinthTestProvider());
            assertTrue(preference != -1);
        }
    }

    /**
     * Asserts that Helix encryption/decryption is successful with a
     * randomly-generated secret key and nonce.
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void usingRandomKeyAndRandomNonce() throws Exception {
        // random key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Helix", "NinthTest");
        SecretKey secretKey = keyGenerator.generateKey();

        // random nonce generated by Cipher#init()
        Cipher cipher = Cipher.getInstance("Helix", "NinthTest");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] cipherTextBytes = cipher.doFinal(PLAINTEXT_STRING.getBytes("UTF-8"));

        // after Cipher#doFinal(), can retrieve the generated MAC:
        AlgorithmParameters params = cipher.getParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);
        byte[] mac = spec.getMac();
        assertEquals(16, mac.length);

        // now decryption...
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        byte[] plainTextBytes = new byte[cipherTextBytes.length];
        cipher.doFinal(cipherTextBytes, 0, cipherTextBytes.length, plainTextBytes);

        String decrypted = new String(plainTextBytes, "UTF-8");
        assertEquals(PLAINTEXT_STRING, decrypted);
    }

    /**
     * Asserts that Helix encryption/decryption is successful with a specified
     * secret key and a randomly-generated nonce.
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void usingSpecifiedKeyAndRandomNonce() throws Exception {
        // specified key
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("Helix", "NinthTest");
        HelixKeySpec keySpec = new HelixKeySpec("KeepMeSecret".getBytes("UTF-8"));
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // random nonce generated by Cipher#init()
        Cipher cipher = Cipher.getInstance("Helix", "NinthTest");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] cipherTextBytes = cipher.doFinal(PLAINTEXT_STRING.getBytes("UTF-8"));

        // after Cipher#doFinal(), can retrieve the generated MAC:
        AlgorithmParameters params = cipher.getParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);
        byte[] mac = spec.getMac();
        assertEquals(16, mac.length);

        // now decryption...
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        byte[] plainTextBytes = new byte[cipherTextBytes.length];
        cipher.doFinal(cipherTextBytes, 0, cipherTextBytes.length, plainTextBytes);

        String decrypted = new String(plainTextBytes, "UTF-8");
        assertEquals(PLAINTEXT_STRING, decrypted);
    }

    /**
     * Asserts that Helix encryption/decryption is successful with a
     * randomly-generated secret key and a specified nonce.
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void usingRandomKeyAndSpecifiedNonce() throws Exception {
        // random key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Helix", "NinthTest");
        SecretKey secretKey = keyGenerator.generateKey();

        // specified nonce
        HelixParameterSpec spec = new HelixParameterSpec("IsIdeallyRotated".getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("Helix", "NinthTest");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherTextBytes = cipher.doFinal(PLAINTEXT_STRING.getBytes("UTF-8"));

        // after Cipher#doFinal(), can retrieve the generated MAC:
        AlgorithmParameters params = cipher.getParameters();
        spec = params.getParameterSpec(HelixParameterSpec.class);
        byte[] mac = spec.getMac();
        assertEquals(16, mac.length);

        // now decryption...
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        byte[] plainTextBytes = new byte[cipherTextBytes.length];
        cipher.doFinal(cipherTextBytes, 0, cipherTextBytes.length, plainTextBytes);

        String decrypted = new String(plainTextBytes, "UTF-8");
        assertEquals(PLAINTEXT_STRING, decrypted);
    }

    /**
     * Asserts that Helix encryption/decryption is successful with a specified
     * secret key and nonce.
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void usingSpecifiedKeyAndSpecifiedNonce() throws Exception {
        // specified key
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("Helix", "NinthTest");
        HelixKeySpec keySpec = new HelixKeySpec("KeepMeSecret".getBytes("UTF-8"));
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // random nonce generated by Cipher#init()
        HelixParameterSpec spec = new HelixParameterSpec("IsIdeallyRotated".getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("Helix", "NinthTest");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] cipherTextBytes = cipher.doFinal(PLAINTEXT_STRING.getBytes("UTF-8"));

        // after Cipher#doFinal(), can retrieve the generated MAC:
        AlgorithmParameters params = cipher.getParameters();
        spec = params.getParameterSpec(HelixParameterSpec.class);
        byte[] mac = spec.getMac();
        assertEquals(16, mac.length);

        // now decryption...
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        byte[] plainTextBytes = new byte[cipherTextBytes.length];
        cipher.doFinal(cipherTextBytes, 0, cipherTextBytes.length, plainTextBytes);

        String decrypted = new String(plainTextBytes, "UTF-8");
        assertEquals(PLAINTEXT_STRING, decrypted);
    }

    /**
     * Asserts that Helix encryption/decryption is successful using byte
     * buffers.
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void usingByteBuffers() throws Exception {
        // random key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Helix", "NinthTest");
        SecretKey secretKey = keyGenerator.generateKey();

        // random nonce generated by Cipher#init()
        Cipher cipher = Cipher.getInstance("Helix", "NinthTest");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] plainTextBytes = PLAINTEXT_STRING.getBytes("UTF-8");
        ByteBuffer cipherTextBuffer = ByteBuffer.allocate(plainTextBytes.length);
        ByteBuffer plainTextBuffer = ByteBuffer.wrap(plainTextBytes, 0, 22);
        cipher.update(plainTextBuffer, cipherTextBuffer);
        plainTextBuffer = ByteBuffer.wrap(plainTextBytes, 22, 22);
        cipher.doFinal(plainTextBuffer, cipherTextBuffer);
        byte[] cipherTextBytes = cipherTextBuffer.array();

        // after Cipher#doFinal(), can retrieve the generated MAC:
        AlgorithmParameters params = cipher.getParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);
        byte[] mac = spec.getMac();
        assertEquals(16, mac.length);

        // now decryption...
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        cipherTextBuffer = ByteBuffer.wrap(cipherTextBytes);
        plainTextBuffer = ByteBuffer.allocate(cipherTextBytes.length);
        cipher.doFinal(cipherTextBuffer, plainTextBuffer);

        String decrypted = new String(plainTextBuffer.array(), "UTF-8");
        assertEquals(PLAINTEXT_STRING, decrypted);
    }

    /**
     * Asserts that the Helix MAC function can be used separately from the
     * cipher.
     * 
     * <p>
     * Since Helix's claim to fame is
     * "encryption and authentication in a <b>single</b> cryptographic primitive,"
     * this is not likely to be a typical usage scenario. However, it <i>is</i>
     * more consistent with the JCE APIs, and is therefore supported.
     * </p>
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void usingStandaloneMacFunction() throws Exception {
        byte[] plainTextBytes = PLAINTEXT_STRING.getBytes("UTF-8");

        // perform the encryption operation to obtain the generated MAC
        SecretKey secretKey = KeyGenerator.getInstance("Helix", "NinthTest").generateKey();
        Cipher cipher = Cipher.getInstance("Helix", "NinthTest");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        cipher.doFinal(plainTextBytes);
        AlgorithmParameters params = cipher.getParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);
        byte[] mac1 = spec.getMac();

        // now perform the MAC function and compare the values
        Mac macFunction = Mac.getInstance("Helix", "NinthTest");
        macFunction.init(secretKey, new HelixParameterSpec(spec.getNonce()));
        byte[] mac2 = macFunction.doFinal(plainTextBytes);

        assertArrayEquals(mac1, mac2);
    }

    /**
     * Asserts that Helix can be used as a PRNG.
     * 
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void generatingPseudoRandomNumbers() throws Exception {
        SecureRandom prng = SecureRandom.getInstance("Helix", "NinthTest");
        /*
         * expected standard deviation of a discrete uniform distribution is
         * SQRT((n**2 - 1) / 12)
         */
        final double expectedStdDev = Math.sqrt((Math.pow(10, 2) - 1) / 12);
        /* actual standard deviation */
        int[] numbers = new int[100000];
        double sumNumbers = 0;
        for (int i = 0; i < numbers.length; ++i) {
            numbers[i] = prng.nextInt(10);
            sumNumbers += numbers[i];
        }
        double mean = sumNumbers / numbers.length;
        double sumDeviations = 0;
        for (int i = 0; i < numbers.length; ++i) {
            sumDeviations += Math.pow(mean - numbers[i], 2);
        }
        double actualStdDev = Math.sqrt(sumDeviations / (numbers.length - 1));

        /* should be sufficient for integration testing purposes */
        assertEquals(expectedStdDev, actualStdDev, 0.01);
    }
}
