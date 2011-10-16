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

import java.security.spec.AlgorithmParameterSpec;

import net.ninthtest.security.Messages;

/**
 * Specifies the <i>nonce</i> (i.e. initialization vector) and optional
 * <i>MAC</i> for Helix cryptographic operations.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixParameterSpec implements AlgorithmParameterSpec {
    private byte[] nonce;

    /*
     * only specified for a a Cipher.DECRYPT_MODE or Cipher.UNWRAP_MODE
     * operation
     */
    private byte[] expectedMac;

    /**
     * Creates a new <tt>HelixParameterSpec</tt> instance using bytes from
     * <tt>nonce</tt> as the Helix <i>nonce</i>.
     * 
     * @param nonce a 16-byte array whose contents will be copied for use as the
     *            Helix <i>nonce</i> (i.e. initialization vector) in an
     *            encryption or decryption operation
     * @throws NullPointerException if <tt>nonce</tt> is null
     * @throws IllegalArgumentException if <tt>nonce</tt> is not exactly 16
     *             bytes in length
     */
    public HelixParameterSpec(final byte[] nonce) {
        if ((nonce == null) || (nonce.length != 16)) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.invalid_nonce"));
        }

        this.nonce = new byte[16];
        System.arraycopy(nonce, 0, this.nonce, 0, 16);
    }

    /**
     * Creates a new <tt>HelixParameterSpec</tt> instance using bytes from
     * <tt>nonce</tt> and <tt>expectedMac</tt> as the Helix <i>nonce</i> and
     * <i>MAC</i>, respectively.
     * 
     * @param nonce a 16-byte array whose contents will be copied for use as the
     *            Helix <i>nonce</i> (i.e. <i>initialization vector</i>) in an
     *            encryption or decryption operation
     * @param expectedMac a 16-byte array whose contents will be copied for use
     *            as the
     *            Helix <i>MAC</i> to authenticate a message
     * @throws NullPointerException if either <tt>nonce</tt> or
     *             <tt>expectedMac</tt> is null
     * @throws IllegalArgumentException if either <tt>nonce</tt> or
     *             <tt>expectedMac</tt> is not exactly 16 bytes in length
     */
    public HelixParameterSpec(final byte[] nonce, final byte[] expectedMac) {
        this(nonce);

        if ((expectedMac == null) || (expectedMac.length != 16)) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.invalid_mac"));
        }

        this.expectedMac = new byte[16];
        System.arraycopy(expectedMac, 0, this.expectedMac, 0, 16);
    }

    /**
     * Returns the <i>nonce</i> used in a Helix cryptographic operation.
     * 
     * @return a copy of the 16-byte nonce
     */
    public byte[] getNonce() {
        byte[] copyOfNonce = new byte[16];
        System.arraycopy(nonce, 0, copyOfNonce, 0, 16);

        return copyOfNonce;
    }

    /**
     * Returns the <i>MAC</i> used to authenticate a message.
     * 
     * @return a copy of the 16-byte MAC, or <tt>null</tt> if the MAC was
     *         not specified for this instance
     */
    public byte[] getMac() {
        if (expectedMac == null) {
            return null;
        }

        byte[] copyOfMac = new byte[16];
        System.arraycopy(expectedMac, 0, copyOfMac, 0, 16);

        return copyOfMac;
    }
}
