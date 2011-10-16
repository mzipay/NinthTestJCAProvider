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

package net.ninthtest.crypto.provider.helix;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.ninthtest.security.Messages;
import net.ninthtest.security.provider.NinthTestProvider;

/**
 * This class generates secret (symmetric) keys for the Helix combined stream
 * cipher and MAC function algorithm.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public final class HelixKeyGenerator extends KeyGeneratorSpi {
    /* the maximum key size in bits */
    private static final int MAXIMUM_KEY_SIZE = 256;

    /* the default key size */
    private static final int DEFAULT_KEY_SIZE = MAXIMUM_KEY_SIZE;

    /* the user-provided key size */
    private int keySize;

    /* the RNG */
    private SecureRandom random;

    /**
     * Creates a new <tt>HelixKeyGenerator</tt> using the default key size
     * and the platform default {@link SecureRandom} implementation.
     * 
     * <p>
     * This constructor also performs the provider self-integrity check.
     * </p>
     */
    public HelixKeyGenerator() {
        NinthTestProvider.doSelfIntegrityCheck();

        keySize = DEFAULT_KEY_SIZE;
        random = new SecureRandom();
    }

    /**
     * Initializes the key generator.
     * 
     * @param random the source of randomness for this generator
     * @see javax.crypto.KeyGeneratorSpi#engineInit(java.security.SecureRandom)
     */
    @Override
    @SuppressWarnings("hiding")
    protected void engineInit(SecureRandom random) {
        keySize = DEFAULT_KEY_SIZE;
        this.random = random;
    }

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     * 
     * @param keySize the size of the keys that this generator should generate,
     *            specified in number of bits (must be a multiple of eight)
     * @param random the source of randomness for this generator
     * @see javax.crypto.KeyGeneratorSpi#engineInit(int,
     *      java.security.SecureRandom)
     */
    @Override
    @SuppressWarnings("hiding")
    protected void engineInit(int keySize, SecureRandom random) {
        if (keySize > MAXIMUM_KEY_SIZE) {
            throw new InvalidParameterException(Messages.getMessage("helix.error.max_key_size_exceeded"));
        } else if ((keySize % 8) != 0) {
            throw new InvalidParameterException(Messages.getMessage("helix.error.invalid_key_size_requested"));
        }

        this.keySize = keySize;
        this.random = random;
    }

    /**
     * Initializes the key generator with the specified parameter set and a
     * user-provided source of randomness.
     * 
     * <p>
     * The <i>Helix</i> key generator does not accept parameters; this method
     * will throw an exception.
     * </p>
     * 
     * @param params the key generation parameters
     * @param random the source of randomness for this generator
     * @throws InvalidAlgorithmParameterException if <tt>params</tt> is
     *             inappropriate for this key generator
     * @see javax.crypto.KeyGeneratorSpi#engineInit(java.security.spec.AlgorithmParameterSpec,
     *      java.security.SecureRandom)
     */
    @Override
    @SuppressWarnings("hiding")
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.paramspec_not_appropriate"));
    }

    /**
     * Generates a secret key.
     * 
     * @return a new, randomly-generated Helix secret key
     * @see javax.crypto.KeyGeneratorSpi#engineGenerateKey()
     */
    @Override
    protected SecretKey engineGenerateKey() {
        byte[] keyBytes = new byte[keySize / 8];
        random.nextBytes(keyBytes);

        return new SecretKeySpec(keyBytes, NinthTestProvider.HELIX);
    }
}
