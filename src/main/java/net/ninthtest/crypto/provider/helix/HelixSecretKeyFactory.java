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

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

import net.ninthtest.security.Messages;
import net.ninthtest.security.provider.NinthTestProvider;

/**
 * A factory for building or retrieving Helix secret keys..
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public final class HelixSecretKeyFactory extends SecretKeyFactorySpi {
    /**
     * Creates a new <tt>HelixSecretKeyFactory</tt> and performs the provider
     * self-integrity check.
     */
    public HelixSecretKeyFactory() {
        NinthTestProvider.doSelfIntegrityCheck();
    }

    /**
     * Generates a {@link SecretKey} object from the provided key specification
     * (key material).
     * 
     * @param keySpec
     *            the Helix secret key material (must be a {@link HelixKeySpec}
     *            )
     * @return a Helix secret key
     * @throws InvalidKeySpecException
     *             if <i>keySpec</i> is <tt>null</tt> or not a
     *             {@link HelixKeySpec}
     * @see javax.crypto.SecretKeyFactorySpi#engineGenerateSecret(java.security.spec.KeySpec)
     */
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if ((keySpec == null) || !(keySpec instanceof HelixKeySpec)) {
            throw new InvalidKeySpecException(Messages.getMessage("helix.error.expect_helix_keyspec"));
        }

        return new SecretKeySpec(((HelixKeySpec) keySpec).getKey(), NinthTestProvider.HELIX);
    }

    /**
     * Returns a specification (key material) of the given key object in the
     * requested format.
     * 
     * @param key
     *            a Helix secret key
     * @param keySpec
     *            specifies the format for the secret key material
     * @return the key material for the Helix secret key
     * @throws InvalidKeySpecException
     *             if <i>key</i> is <tt>null</tt> or not a Helix secret key in
     *             "RAW" format; or if <i>keySpec</i> is <tt>null</tt> or not
     *             the class of {@link HelixKeySpec}); or if an error occurs
     *             while creating the {@link HelixKeySpec} from the secret key
     * @see javax.crypto.SecretKeyFactorySpi#engineGetKeySpec(javax.crypto.SecretKey,
     *      java.lang.Class)
     */
    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, @SuppressWarnings("rawtypes") Class keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException(Messages.getMessage("error.secret_key_is_required"));
        } else if (!NinthTestProvider.HELIX.equals(key.getAlgorithm()) || !"RAW".equals(key.getFormat())) {
            throw new InvalidKeySpecException(Messages.getMessage("helix.error.expect_helix_secret_key"));
        } else if ((keySpec == null) || !keySpec.equals(HelixKeySpec.class)) {
            throw new InvalidKeySpecException(Messages.getMessage("helix.error.expect_helix_keyspec_class"));
        }

        try {
            return new HelixKeySpec(key.getEncoded());
        } catch (IllegalArgumentException ex) {
            throw new InvalidKeySpecException(Messages.getMessage("helix.error.failed_to_create_helix_keyspec"), ex);
        }
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this secret-key factory.
     * 
     * <p>
     * Only the first 32 bytes from <tt>key</tt> are used in the translation.
     * </p>
     * 
     * @param key
     *            a secret key (presumably <b>not</b> a Helix secret key)
     * @return a Helix secret key
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt>; or if <i>key</i> cannot be
     *             used to create a Helix secret key
     * @see javax.crypto.SecretKeyFactorySpi#engineTranslateKey(javax.crypto.SecretKey)
     */
    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException(Messages.getMessage("error.secret_key_is_required"));
        }

        HelixKeySpec keySpec = null;
        try {
            keySpec = new HelixKeySpec(key.getEncoded());
        } catch (IllegalArgumentException ex) {
            throw new InvalidKeyException(Messages.getMessage("helix.error.failed_to_create_helix_key_spec"), ex);
        }

        return new SecretKeySpec(keySpec.getKey(), NinthTestProvider.HELIX);
    }
}
