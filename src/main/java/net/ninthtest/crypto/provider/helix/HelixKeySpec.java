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

import java.security.spec.KeySpec;

import net.ninthtest.security.Messages;

/**
 * A (transparent) specification of the key material that constitutes a Helix
 * secret key.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class HelixKeySpec implements KeySpec {
    /* the maximum length of a Helix key in bytes */
    private static final int MAXIMUM_KEY_LENGTH = 32;

    /* the raw bytes of the Helix secret key */
    private final byte[] key;

    /**
     * Creates a new <tt>HelixKeySpec</tt> using the first 32 bytes from
     * <i>key</i> as the key material for the Helix key.
     * 
     * <p>
     * If <i>key</i> contains less than 32 bytes, only <tt>key.length</tt> bytes
     * of key material will be used.
     * </p>
     * 
     * @param key the buffer containing Helix key material (bytes are copied to
     *            protect against subsequent modification)
     */
    public HelixKeySpec(byte[] key) {
        this(key, 0);
    }

    /**
     * Creates a new <tt>HelixKeySpec</tt> using the first 32 bytes from
     * <i>key</i>, beginning at <i>offset</i> (inclusive), as the key material
     * for the Helix key.
     * 
     * <p>
     * A maximum of 32 bytes of key material will be used. In other words, the
     * number of bytes of key material will be the <b>lesser</b> of
     * <tt>(key.length - offset)</tt> and <tt>32</tt>.
     * </p>
     * 
     * @param key the buffer containing Helix key material (bytes are copied to
     *            protect against subsequent modification)
     * @param offset the index into <i>key</i> where the Helix key material
     *            begins
     */
    public HelixKeySpec(byte[] key, int offset) {
        if (key == null) {
            throw new IllegalArgumentException(Messages.getMessage("error.key_material_is_required"));
        } else if ((offset < 0) || (offset >= key.length)) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_key_material_offset"));
        }

        int length = Math.min(key.length - offset, MAXIMUM_KEY_LENGTH);
        this.key = new byte[length];
        System.arraycopy(key, offset, this.key, 0, length);
    }

    /**
     * Returns the key material for the Helix cryptographic key.
     * 
     * @return a copy of the Helix key material
     */
    public byte[] getKey() {
        byte[] copyOfKey = new byte[key.length];
        System.arraycopy(key, 0, copyOfKey, 0, key.length);

        return copyOfKey;
    }
}
