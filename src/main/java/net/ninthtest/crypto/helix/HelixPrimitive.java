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

package net.ninthtest.crypto.helix;

/**
 * A cryptographic primitive for the Helix combined stream cipher and MAC
 * function.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 * @see "http://www.macfergus.com/helix/index.html"
 */
public interface HelixPrimitive {
    /**
     * Processes the next sequence of input bytes.
     * 
     * @param part the next sequence of bytes to be processed by this primitive
     * @return an array of bytes representing plaintext or ciphertext, depending
     *         on the operation mode of this primitive
     */
    public byte[] feed(final byte[] part);

    /**
     * Returns the number of bytes that are currently buffered.
     * 
     * @return the buffered byte count
     */
    public int bufferSize();

    /**
     * Completes a Helix encryption/decryption operation.
     * 
     * <p>
     * If this method completes successfully, the generated MAC can be retrieved
     * using the {@link #getGeneratedMac()} method.
     * </p>
     * 
     * @param part the last input bytes to be fed
     * @return the ciphertext (encryption) or plaintext (decryption) bytes
     */
    public byte[] finish(final byte[] part);

    /**
     * Returns the MAC that was generated following a successful
     * encryption/decryption operation.
     * 
     * @return the generated MAC bytes
     */
    public byte[] getGeneratedMac();
}
