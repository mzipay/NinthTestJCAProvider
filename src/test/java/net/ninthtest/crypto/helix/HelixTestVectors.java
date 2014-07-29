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

/**
 * Defines the official Helix test vectors for use by all unit and functional
 * test cases.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 * @see "http://www.schneier.com/paper-helix.html"
 */
public interface HelixTestVectors {
    /** The index into a test vector where the secret key bytes can be found. */
    public static final int KEY = 0;

    /** The index into a test vector where the nonce bytes can be found. */
    public static final int NONCE = 1;

    /** The index into a test vector where the working key bytes can be found. */
    public static final int WORKING_KEY = 2;

    /** The index into a test vector where the plaintext bytes can be found. */
    public static final int PLAINTEXT = 3;

    /** The index into a test vector where the ciphertext bytes can be found. */
    public static final int CIPHERTEXT = 4;

    /** The index into a test vector where the MAC bytes can be found. */
    public static final int MAC = 5;

    /**
     * Helix test vector #1.
     * 
     * @see "http://www.schneier.com/paper-helix.html"
     */
    public static final byte[][] TEST_VECTOR_1 = new byte[][] {
            new byte[] {},
            new byte[16],
            new byte[] {(byte) 0xa9, (byte) 0x3b, (byte) 0x6e, (byte) 0x32, (byte) 0xbc, (byte) 0x23, (byte) 0x4f,
                    (byte) 0x6c, (byte) 0x32, (byte) 0x6c, (byte) 0x0f, (byte) 0x82, (byte) 0x74, (byte) 0xff,
                    (byte) 0xa2, (byte) 0x41, (byte) 0xe3, (byte) 0xda, (byte) 0x57, (byte) 0x7d, (byte) 0xef,
                    (byte) 0x7c, (byte) 0x1b, (byte) 0x64, (byte) 0xaf, (byte) 0x78, (byte) 0x7c, (byte) 0x38,
                    (byte) 0xdc, (byte) 0xef, (byte) 0xe3, (byte) 0xde},
            new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00},
            new byte[] {(byte) 0x70, (byte) 0x44, (byte) 0xc9, (byte) 0xbe, (byte) 0x48, (byte) 0xae, (byte) 0x89,
                    (byte) 0x22, (byte) 0x66, (byte) 0xe4},
            new byte[] {(byte) 0x65, (byte) 0xbe, (byte) 0x7a, (byte) 0x60, (byte) 0xfd, (byte) 0x3b, (byte) 0x8a,
                    (byte) 0x5e, (byte) 0x31, (byte) 0x61, (byte) 0x80, (byte) 0x80, (byte) 0x56, (byte) 0x32,
                    (byte) 0xd8, (byte) 0x10}};

    /**
     * Helix test vector #2.
     * 
     * @see "http://www.schneier.com/paper-helix.html"
     */
    public static final byte[][] TEST_VECTOR_2 = new byte[][] {
            new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x05,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x07, (byte) 0x00, (byte) 0x00, (byte) 0x00},
            new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00},
            new byte[] {(byte) 0x6e, (byte) 0xe9, (byte) 0xa7, (byte) 0x6c, (byte) 0xbd, (byte) 0x0b, (byte) 0xf6,
                    (byte) 0x20, (byte) 0xa6, (byte) 0xd9, (byte) 0xb7, (byte) 0x59, (byte) 0x49, (byte) 0xd3,
                    (byte) 0x39, (byte) 0x95, (byte) 0x04, (byte) 0xf8, (byte) 0x4a, (byte) 0xd6, (byte) 0x83,
                    (byte) 0x12, (byte) 0xf9, (byte) 0x06, (byte) 0xed, (byte) 0xd1, (byte) 0xa6, (byte) 0x98,
                    (byte) 0x9e, (byte) 0xc8, (byte) 0x9d, (byte) 0x45},
            new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x05,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x07, (byte) 0x00, (byte) 0x00, (byte) 0x00},
            new byte[] {(byte) 0x7a, (byte) 0x72, (byte) 0xa7, (byte) 0x5b, (byte) 0x62, (byte) 0x50, (byte) 0x38,
                    (byte) 0x0b, (byte) 0x69, (byte) 0x75, (byte) 0x1c, (byte) 0xd1, 0x28, (byte) 0x30, (byte) 0x8d,
                    (byte) 0x9a, (byte) 0x0c, (byte) 0x74, (byte) 0x46, (byte) 0xa3, (byte) 0xbf, (byte) 0x3f,
                    (byte) 0x99, (byte) 0xe6, (byte) 0x65, (byte) 0x56, (byte) 0xb9, (byte) 0xc1, (byte) 0x18,
                    (byte) 0xca, (byte) 0x7d, (byte) 0x87},
            new byte[] {(byte) 0xe4, (byte) 0xe5, (byte) 0x49, (byte) 0x01, (byte) 0xc5, (byte) 0x0b, (byte) 0x34,
                    (byte) 0xe7, (byte) 0x80, (byte) 0xc0, (byte) 0x9c, (byte) 0x39, (byte) 0xb1, (byte) 0x09,
                    (byte) 0xa1, (byte) 0x17}};

    /**
     * Helix test vector #3.
     * 
     * @see "http://www.schneier.com/paper-helix.html"
     */
    public static final byte[][] TEST_VECTOR_3 = new byte[][] {
            new byte[] {(byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x69, (byte) 0x78},
            new byte[] {(byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
                    (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64,
                    (byte) 0x65, (byte) 0x66},
            new byte[] {(byte) 0x6c, (byte) 0x1e, (byte) 0xd7, (byte) 0x7a, (byte) 0xcb, (byte) 0xa3, (byte) 0xa1,
                    (byte) 0xd2, (byte) 0x8f, (byte) 0x1c, (byte) 0xd6, (byte) 0x20, (byte) 0x6d, (byte) 0xf1,
                    (byte) 0x15, (byte) 0xda, (byte) 0xf4, (byte) 0x03, (byte) 0x28, (byte) 0x4a, (byte) 0x73,
                    (byte) 0x9b, (byte) 0xb6, (byte) 0x9f, (byte) 0x35, (byte) 0x7a, (byte) 0x85, (byte) 0xf5,
                    (byte) 0x51, (byte) 0x32, (byte) 0x11, (byte) 0x39},
            new byte[] {(byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f, (byte) 0x2c, (byte) 0x20,
                    (byte) 0x77, (byte) 0x6f, (byte) 0x72, (byte) 0x6c, (byte) 0x64, (byte) 0x21},
            new byte[] {(byte) 0x6c, (byte) 0x4c, (byte) 0x27, (byte) 0xb9, (byte) 0x7a, (byte) 0x82, (byte) 0xa0,
                    (byte) 0xc5, (byte) 0x80, (byte) 0x2c, (byte) 0x23, (byte) 0xf2, (byte) 0x0d},
            new byte[] {(byte) 0x6c, (byte) 0x82, (byte) 0xd1, (byte) 0xaa, (byte) 0x3b, (byte) 0x90, (byte) 0x5f,
                    (byte) 0x12, (byte) 0xf1, (byte) 0x44, (byte) 0x3f, (byte) 0xa7, (byte) 0xf6, (byte) 0xa1,
                    (byte) 0x01, (byte) 0xd2}};
}
