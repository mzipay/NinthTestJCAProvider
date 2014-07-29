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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

import net.ninthtest.crypto.helix.HelixEncryption;
import net.ninthtest.security.Messages;
import net.ninthtest.security.provider.NinthTestProvider;

/**
 * This class provides the MAC generation operation for the Helix stream cipher.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public final class HelixMac extends MacSpi {
    private SecretKey secret;

    /* provides the nonce */
    private HelixParameterSpec paramSpec;

    /* use a Helix encryption primitive to generate the MAC */
    private HelixEncryption primitive;

    /**
     * Creates a new <tt>HelixMac</tt> and performs the provider self-integrity
     * check.
     */
    public HelixMac() {
        NinthTestProvider.doSelfIntegrityCheck();
    }

    /**
     * Returns the length of the MAC in bytes.
     * 
     * @return the length of a Helix MAC expressed in bytes (always <tt>16</tt>
     *         )
     * @see javax.crypto.MacSpi#engineGetMacLength()
     */
    @Override
    protected int engineGetMacLength() {
        return 16;
    }

    /**
     * Initializes the MAC with the given (secret) key and algorithm parameters.
     * 
     * <p>
     * If a MAC is non-<tt>null</tt> in <i>params</i>, it is ignored.
     * </p>
     * 
     * @param key
     *            the secret key for an MAC generation (encryption) operation
     *            (must be a Helix {@link SecretKey})
     * @param params
     *            the algorithm parameters (must be a {@link HelixParameterSpec}
     *            )
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt> or not a Helix
     *             {@link SecretKey}
     * @throws InvalidAlgorithmParameterException
     *             if <i>params</i> is <tt>null</tt> or not a
     *             {@link HelixParameterSpec}
     * @see javax.crypto.MacSpi#engineInit(java.security.Key,
     *      java.security.spec.AlgorithmParameterSpec)
     */
    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        clear();

        if ((key == null) || !NinthTestProvider.HELIX.equals(key.getAlgorithm()) || !(key instanceof SecretKey)) {
            throw new InvalidKeyException(Messages.getMessage("helix.error.expect_secret_key"));
        } else if ((params == null) || !(params instanceof HelixParameterSpec)) {
            throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.expect_helix_paramspec"));
        }

        secret = (SecretKey) key;
        paramSpec = (HelixParameterSpec) params;
        primitive = new HelixEncryption(key.getEncoded(), paramSpec.getNonce());
    }

    /*
     * Resets the internal state of this MAC so that it can be re-used.
     */
    private void clear() {
        secret = null;
        paramSpec = null;
        primitive = null;
    }

    /**
     * Processes the given byte.
     * 
     * @param input
     *            the input byte to be processed
     * @see javax.crypto.MacSpi#engineUpdate(byte)
     */
    @Override
    protected void engineUpdate(byte input) {
        primitive.feed(new byte[] {input});
    }

    /**
     * Processes the first <tt>len</tt> bytes in input, starting at
     * <tt>offset</tt> inclusive.
     * 
     * @param input
     *            the input buffer
     * @param offset
     *            the index into <i>input</i> where the input bytes begin
     * @param len
     *            the number of bytes to be used from <i>input</i> (beginning at
     *            <i>offset</i>)
     * @see javax.crypto.MacSpi#engineUpdate(byte[], int, int)
     */
    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (input == null) {
            throw new IllegalArgumentException(Messages.getMessage("error.input_buffer_is_required"));
        } else if ((offset < 0) || (offset >= input.length)) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_input_offset"));
        } else if ((len < 0) || (len > (input.length - offset))) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_input_length"));
        }

        byte[] part = new byte[len];
        System.arraycopy(input, offset, part, 0, len);

        primitive.feed(part);
    }

    /**
     * Completes the MAC computation and resets the MAC for further use,
     * maintaining the secret key that the MAC was initialized with.
     * 
     * @return the generated 16-byte MAC
     * @see javax.crypto.MacSpi#engineDoFinal()
     */
    @Override
    protected byte[] engineDoFinal() {
        primitive.finish(new byte[0]);
        byte[] generatedMac = primitive.getGeneratedMac();

        engineReset();

        return generatedMac;
    }

    /**
     * Resets the MAC for further use, maintaining the secret key that the MAC
     * was initialized with.
     * 
     * <p>
     * The Helix nonce is also maintained. Re-using a <tt>HelixMac</tt> in this
     * manner is <b>not recommended</b>; instead, re-initialize the <tt>Mac</tt>
     * instance with a new nonce.
     * </p>
     * 
     * @see javax.crypto.MacSpi#engineReset()
     */
    @Override
    protected void engineReset() {
        primitive = new HelixEncryption(secret.getEncoded(), paramSpec.getNonce());
    }
}
