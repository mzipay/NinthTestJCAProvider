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

package net.ninthtest.crypto.helix;

import java.util.Arrays;

import net.ninthtest.crypto.MessageAuthenticationException;
import net.ninthtest.security.Messages;

/**
 * A Helix primitive for a single decryption operation.
 * 
 * <p>
 * This primitive can be used for decryption only, or for
 * decryption-with-MAC-verification, based upon how the instance is constructed.
 * </p>
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixDecryption extends HelixImpl {
    /*
     * Holds the MAC that is expected to be generated after the decryption
     * operation completes successfully.
     */
    private final byte[] expectedMac;

    /**
     * Creates a new <tt>HelixDecryption</tt> primitive using the specified key
     * and nonce.
     * 
     * <p>
     * A <tt>HelixDecryption</tt> primitive constructed in this way will
     * <b>not</b> perform MAC verification. However, the generated MAC is still
     * retrievable (via the {@link #getGeneratedMac()} method) after the
     * successful completion of the decryption operation.
     * </p>
     * 
     * @param key
     *            the Helix key (cannot exceed 32 bytes in length)
     * @param nonce
     *            the Helix nonce (must be exactly 16 bytes in length)
     */
    public HelixDecryption(final byte[] key, final byte[] nonce) {
        this(key, nonce, null);
    }

    /**
     * Creates a new <tt>HelixDecryption</tt> primitive using the specified key,
     * nonce, and expected MAC.
     * 
     * <p>
     * A <tt>HelixDecryption</tt> primitive constructed in this way will verify
     * the generated MAC against <i>expectedMac</i> on the successful completion
     * of the decryption operation <b>if</b> <i>expectedMac</i> is not
     * <tt>null</tt>.
     * </p>
     * 
     * @param key
     *            the Helix key (cannot exceed 32 bytes in length)
     * @param nonce
     *            the Helix nonce (must be exactly 16 bytes in length)
     * @param expectedMac
     *            the Helix MAC that is expected to be generated after the
     *            decryption operation completes successfully (or <tt>null</tt>
     *            to bypass MAC verification)
     */
    public HelixDecryption(final byte[] key, final byte[] nonce, final byte[] expectedMac) {
        super(key, nonce);

        if ((expectedMac != null) && (expectedMac.length != 16)) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.invalid_mac_length"));
        }

        this.expectedMac = expectedMac;
    }

    /**
     * {@inheritDoc}
     * 
     * @param cipherTextBytes
     *            the final group of ciphertext bytes to be decrypted
     * @return the final group of decrypted (plaintext) bytes
     * @throws MessageAuthenticationException
     *             if this primitive was constructed with an expected MAC, and
     *             MAC verification fails
     */
    @Override
    public byte[] finish(byte[] cipherTextBytes) {
        byte[] plainTextBytes = super.finish(cipherTextBytes);

        if (expectedMac != null) {
            byte[] generatedMac = getGeneratedMac();

            if (!Arrays.equals(expectedMac, generatedMac)) {
                throw new MessageAuthenticationException(Messages.getMessage("error.mac_mismatch"), expectedMac,
                        generatedMac);
            }
        }

        return plainTextBytes;
    }

    /**
     * {@inheritDoc}
     * 
     * @param cipherTextWords
     *            the next group of ciphertext words to be
     * @param mask
     *            a 32-bit integer used to mask off extra bytes (if any) on the
     *            last group of ciphertext words
     * @return the decrypted words (plaintext)
     */
    @Override
    protected int[] transformWords(int[] cipherTextWords, int mask) {
        int[] plainTextWords = new int[cipherTextWords.length];

        /* decryption loop */
        for (int x = 0; x < cipherTextWords.length; ++x) {
            plainTextWords[x] = (cipherTextWords[x] ^ nextStateWord()) & mask;
            doBlock(plainTextWords[x]);
        }

        return plainTextWords;
    }
}
