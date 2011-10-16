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
 * A Helix primitive for a single encryption operation.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixEncryption extends HelixImpl {
    /**
     * Creates a new <tt>HelixEncryption</tt> primitive using the specified key
     * and nonce.
     * 
     * @param key the Helix key, (cannot exceed 32 bytes in length)
     * @param nonce the Helix nonce (must be exactly 16 bytes in length)
     */
    public HelixEncryption(final byte[] key, final byte[] nonce) {
        super(key, nonce);
    }

    /**
     * {@inheritDoc}
     * 
     * @param plainTextWords the next group of plaintext words to be encrypted
     * @param mask <i>(ignored)</i>
     * @return the encrypted words (ciphertext)
     */
    @Override
    protected int[] transformWords(int[] plainTextWords, int mask) {
        int[] cipherTextWords = new int[plainTextWords.length];

        /* encryption loop */
        for (int x = 0; x < plainTextWords.length; ++x) {
            cipherTextWords[x] = (plainTextWords[x] ^ nextStateWord());
            doBlock(plainTextWords[x]);
        }

        return cipherTextWords;
    }
}
