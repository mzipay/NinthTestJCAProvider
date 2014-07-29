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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.ninthtest.crypto.MessageAuthenticationException;
import net.ninthtest.crypto.helix.HelixTestVectors;
import net.ninthtest.security.provider.NinthTestProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * The unit test case for {@link HelixCipher}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixCipherTest implements HelixTestVectors {
    /* Used to test key (un)wrapping of a public key. */
    private static final byte[] DSA_PUBLIC_KEY_MATERIAL = new byte[] {(byte) 0x30, (byte) 0x81, (byte) 0xf0,
            (byte) 0x30, (byte) 0x81, (byte) 0xa8, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0xce, (byte) 0x38, (byte) 0x04, (byte) 0x01, (byte) 0x30, (byte) 0x81, (byte) 0x9c, (byte) 0x02,
            (byte) 0x41, (byte) 0x00, (byte) 0xfc, (byte) 0xa6, (byte) 0x82, (byte) 0xce, (byte) 0x8e, (byte) 0x12,
            (byte) 0xca, (byte) 0xba, (byte) 0x26, (byte) 0xef, (byte) 0xcc, (byte) 0xf7, (byte) 0x11, (byte) 0x0e,
            (byte) 0x52, (byte) 0x6d, (byte) 0xb0, (byte) 0x78, (byte) 0xb0, (byte) 0x5e, (byte) 0xde, (byte) 0xcb,
            (byte) 0xcd, (byte) 0x1e, (byte) 0xb4, (byte) 0xa2, (byte) 0x08, (byte) 0xf3, (byte) 0xae, (byte) 0x16,
            (byte) 0x17, (byte) 0xae, (byte) 0x01, (byte) 0xf3, (byte) 0x5b, (byte) 0x91, (byte) 0xa4, (byte) 0x7e,
            (byte) 0x6d, (byte) 0xf6, (byte) 0x34, (byte) 0x13, (byte) 0xc5, (byte) 0xe1, (byte) 0x2e, (byte) 0xd0,
            (byte) 0x89, (byte) 0x9b, (byte) 0xcd, (byte) 0x13, (byte) 0x2a, (byte) 0xcd, (byte) 0x50, (byte) 0xd9,
            (byte) 0x91, (byte) 0x51, (byte) 0xbd, (byte) 0xc4, (byte) 0x3e, (byte) 0xe7, (byte) 0x37, (byte) 0x59,
            (byte) 0x2e, (byte) 0x17, (byte) 0x02, (byte) 0x15, (byte) 0x00, (byte) 0x96, (byte) 0x2e, (byte) 0xdd,
            (byte) 0xcc, (byte) 0x36, (byte) 0x9c, (byte) 0xba, (byte) 0x8e, (byte) 0xbb, (byte) 0x26, (byte) 0x0e,
            (byte) 0xe6, (byte) 0xb6, (byte) 0xa1, (byte) 0x26, (byte) 0xd9, (byte) 0x34, (byte) 0x6e, (byte) 0x38,
            (byte) 0xc5, (byte) 0x02, (byte) 0x40, (byte) 0x67, (byte) 0x84, (byte) 0x71, (byte) 0xb2, (byte) 0x7a,
            (byte) 0x9c, (byte) 0xf4, (byte) 0x4e, (byte) 0xe9, (byte) 0x1a, (byte) 0x49, (byte) 0xc5, (byte) 0x14,
            (byte) 0x7d, (byte) 0xb1, (byte) 0xa9, (byte) 0xaa, (byte) 0xf2, (byte) 0x44, (byte) 0xf0, (byte) 0x5a,
            (byte) 0x43, (byte) 0x4d, (byte) 0x64, (byte) 0x86, (byte) 0x93, (byte) 0x1d, (byte) 0x2d, (byte) 0x14,
            (byte) 0x27, (byte) 0x1b, (byte) 0x9e, (byte) 0x35, (byte) 0x03, (byte) 0x0b, (byte) 0x71, (byte) 0xfd,
            (byte) 0x73, (byte) 0xda, (byte) 0x17, (byte) 0x90, (byte) 0x69, (byte) 0xb3, (byte) 0x2e, (byte) 0x29,
            (byte) 0x35, (byte) 0x63, (byte) 0x0e, (byte) 0x1c, (byte) 0x20, (byte) 0x62, (byte) 0x35, (byte) 0x4d,
            (byte) 0x0d, (byte) 0xa2, (byte) 0x0a, (byte) 0x6c, (byte) 0x41, (byte) 0x6e, (byte) 0x50, (byte) 0xbe,
            (byte) 0x79, (byte) 0x4c, (byte) 0xa4, (byte) 0x03, (byte) 0x43, (byte) 0x00, (byte) 0x02, (byte) 0x40,
            (byte) 0x40, (byte) 0x2d, (byte) 0x4c, (byte) 0x89, (byte) 0x21, (byte) 0x44, (byte) 0xa9, (byte) 0x1e,
            (byte) 0x41, (byte) 0xcb, (byte) 0xd2, (byte) 0x30, (byte) 0x01, (byte) 0xfb, (byte) 0x05, (byte) 0xb8,
            (byte) 0xae, (byte) 0xf3, (byte) 0x08, (byte) 0x16, (byte) 0xdd, (byte) 0xd6, (byte) 0x03, (byte) 0xb9,
            (byte) 0xda, (byte) 0x0b, (byte) 0xf6, (byte) 0xfc, (byte) 0xae, (byte) 0x4f, (byte) 0x95, (byte) 0xd8,
            (byte) 0x29, (byte) 0x37, (byte) 0xb6, (byte) 0xeb, (byte) 0x29, (byte) 0xbd, (byte) 0xcc, (byte) 0x75,
            (byte) 0x83, (byte) 0xf7, (byte) 0x0a, (byte) 0x80, (byte) 0x69, (byte) 0xb2, (byte) 0xac, (byte) 0x80,
            (byte) 0x71, (byte) 0x02, (byte) 0x81, (byte) 0x20, (byte) 0x9c, (byte) 0x19, (byte) 0x65, (byte) 0xb0,
            (byte) 0xcd, (byte) 0xf8, (byte) 0x7a, (byte) 0x8f, (byte) 0xd9, (byte) 0xa7, (byte) 0x33, (byte) 0x52};

    /*
     * Used to test key (un)wrapping of a public key; assumes test vector #3 key
     * and nonce.
     */
    private static final byte[] DSA_WRAPPED_PUBLIC_KEY = new byte[] {(byte) 0x14, (byte) 0xa8, (byte) 0xbb,
            (byte) 0xe5, (byte) 0x09, (byte) 0x82, (byte) 0x15, (byte) 0xb0, (byte) 0x60, (byte) 0x49, (byte) 0xb0,
            (byte) 0xe4, (byte) 0x4d, (byte) 0xc4, (byte) 0x56, (byte) 0x8d, (byte) 0x4a, (byte) 0x02, (byte) 0xe8,
            (byte) 0x7f, (byte) 0xe4, (byte) 0x1c, (byte) 0x2e, (byte) 0x78, (byte) 0x1c, (byte) 0x73, (byte) 0x97,
            (byte) 0x6a, (byte) 0x3d, (byte) 0x6f, (byte) 0x5d, (byte) 0x33, (byte) 0x73, (byte) 0xde, (byte) 0x18,
            (byte) 0x14, (byte) 0x4c, (byte) 0xf1, (byte) 0x08, (byte) 0x6a, (byte) 0x58, (byte) 0x3d, (byte) 0xb8,
            (byte) 0x82, (byte) 0xf0, (byte) 0x3b, (byte) 0x37, (byte) 0xab, (byte) 0x85, (byte) 0x5e, (byte) 0x6c,
            (byte) 0x77, (byte) 0xfe, (byte) 0x43, (byte) 0xa2, (byte) 0xc6, (byte) 0x47, (byte) 0x51, (byte) 0x45,
            (byte) 0x0d, (byte) 0xd3, (byte) 0x5b, (byte) 0xe5, (byte) 0xc4, (byte) 0xd1, (byte) 0x1a, (byte) 0x13,
            (byte) 0xc4, (byte) 0xfe, (byte) 0xa0, (byte) 0x76, (byte) 0xf4, (byte) 0x10, (byte) 0x4a, (byte) 0xa5,
            (byte) 0xe1, (byte) 0xb2, (byte) 0x0c, (byte) 0x32, (byte) 0xa6, (byte) 0x63, (byte) 0x2e, (byte) 0x8b,
            (byte) 0xd5, (byte) 0xfd, (byte) 0x7e, (byte) 0x71, (byte) 0x4b, (byte) 0x8b, (byte) 0x46, (byte) 0x45,
            (byte) 0xc9, (byte) 0x85, (byte) 0xf2, (byte) 0x23, (byte) 0xe0, (byte) 0xb9, (byte) 0x5e, (byte) 0x21,
            (byte) 0x3e, (byte) 0x5d, (byte) 0x20, (byte) 0xee, (byte) 0xff, (byte) 0x9d, (byte) 0x36, (byte) 0x3b,
            (byte) 0x32, (byte) 0xa3, (byte) 0x1d, (byte) 0xf8, (byte) 0x60, (byte) 0x45, (byte) 0xb0, (byte) 0xf7,
            (byte) 0xf8, (byte) 0x07, (byte) 0x5d, (byte) 0x8b, (byte) 0x47, (byte) 0xea, (byte) 0x5b, (byte) 0x33,
            (byte) 0x21, (byte) 0x92, (byte) 0x4b, (byte) 0xf2, (byte) 0x9a, (byte) 0xf5, (byte) 0x15, (byte) 0x13,
            (byte) 0x98, (byte) 0x50, (byte) 0x8a, (byte) 0xfa, (byte) 0x99, (byte) 0xb1, (byte) 0x89, (byte) 0xf7,
            (byte) 0xf8, (byte) 0x2a, (byte) 0x0d, (byte) 0xf5, (byte) 0x08, (byte) 0xd9, (byte) 0x0d, (byte) 0x29,
            (byte) 0x5c, (byte) 0x7a, (byte) 0x12, (byte) 0x03, (byte) 0x1d, (byte) 0x4c, (byte) 0x82, (byte) 0xec,
            (byte) 0xa4, (byte) 0xd9, (byte) 0x9b, (byte) 0x78, (byte) 0x5f, (byte) 0x4f, (byte) 0xe5, (byte) 0x73,
            (byte) 0x66, (byte) 0xf9, (byte) 0xa8, (byte) 0xff, (byte) 0xbb, (byte) 0x9a, (byte) 0x97, (byte) 0x32,
            (byte) 0xf1, (byte) 0xa8, (byte) 0xe9, (byte) 0xf0, (byte) 0x16, (byte) 0x19, (byte) 0x73, (byte) 0xfb,
            (byte) 0xaa, (byte) 0x08, (byte) 0x74, (byte) 0x0a, (byte) 0xc2, (byte) 0x14, (byte) 0x60, (byte) 0x9d,
            (byte) 0x46, (byte) 0x11, (byte) 0x2b, (byte) 0xbf, (byte) 0x29, (byte) 0xe6, (byte) 0x3d, (byte) 0x1e,
            (byte) 0x4f, (byte) 0x71, (byte) 0x65, (byte) 0x09, (byte) 0xf4, (byte) 0xe1, (byte) 0x37, (byte) 0x8d,
            (byte) 0xea, (byte) 0x4d, (byte) 0x84, (byte) 0xe9, (byte) 0x44, (byte) 0xa3, (byte) 0x0f, (byte) 0xb5,
            (byte) 0x7c, (byte) 0x87, (byte) 0x96, (byte) 0x7e, (byte) 0x47, (byte) 0xf9, (byte) 0x02, (byte) 0xae,
            (byte) 0x9b, (byte) 0xc8, (byte) 0x5f, (byte) 0x78, (byte) 0x13, (byte) 0x16, (byte) 0x72, (byte) 0x7f,
            (byte) 0x57, (byte) 0x6e, (byte) 0x06, (byte) 0xd4, (byte) 0xd3, (byte) 0x69, (byte) 0x95, (byte) 0x7d,
            (byte) 0xc8, (byte) 0x28, (byte) 0x77, (byte) 0x71, (byte) 0x5b, (byte) 0xb4, (byte) 0x91, (byte) 0xfe};

    /*
     * Used to test key (un)wrapping of a public key; assumes test vector #3 key
     * and nonce.
     */
    private static final byte[] DSA_WRAPPED_PUBLIC_KEY_MAC = new byte[] {(byte) 0x47, (byte) 0xb0, (byte) 0xcb,
            (byte) 0x3c, (byte) 0x10, (byte) 0xd8, (byte) 0xd0, (byte) 0x79, (byte) 0x6e, (byte) 0x16, (byte) 0x98,
            (byte) 0xff, (byte) 0xc7, (byte) 0x8c, (byte) 0x94, (byte) 0x24};

    /* Used to test key (un)wrapping of a private key. */
    private static final byte[] DSA_PRIVATE_KEY_MATERIAL = new byte[] {(byte) 0x30, (byte) 0x81, (byte) 0xc6,
            (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, (byte) 0x81, (byte) 0xa8, (byte) 0x06, (byte) 0x07,
            (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x38, (byte) 0x04, (byte) 0x01, (byte) 0x30,
            (byte) 0x81, (byte) 0x9c, (byte) 0x02, (byte) 0x41, (byte) 0x00, (byte) 0xfc, (byte) 0xa6, (byte) 0x82,
            (byte) 0xce, (byte) 0x8e, (byte) 0x12, (byte) 0xca, (byte) 0xba, (byte) 0x26, (byte) 0xef, (byte) 0xcc,
            (byte) 0xf7, (byte) 0x11, (byte) 0x0e, (byte) 0x52, (byte) 0x6d, (byte) 0xb0, (byte) 0x78, (byte) 0xb0,
            (byte) 0x5e, (byte) 0xde, (byte) 0xcb, (byte) 0xcd, (byte) 0x1e, (byte) 0xb4, (byte) 0xa2, (byte) 0x08,
            (byte) 0xf3, (byte) 0xae, (byte) 0x16, (byte) 0x17, (byte) 0xae, (byte) 0x01, (byte) 0xf3, (byte) 0x5b,
            (byte) 0x91, (byte) 0xa4, (byte) 0x7e, (byte) 0x6d, (byte) 0xf6, (byte) 0x34, (byte) 0x13, (byte) 0xc5,
            (byte) 0xe1, (byte) 0x2e, (byte) 0xd0, (byte) 0x89, (byte) 0x9b, (byte) 0xcd, (byte) 0x13, (byte) 0x2a,
            (byte) 0xcd, (byte) 0x50, (byte) 0xd9, (byte) 0x91, (byte) 0x51, (byte) 0xbd, (byte) 0xc4, (byte) 0x3e,
            (byte) 0xe7, (byte) 0x37, (byte) 0x59, (byte) 0x2e, (byte) 0x17, (byte) 0x02, (byte) 0x15, (byte) 0x00,
            (byte) 0x96, (byte) 0x2e, (byte) 0xdd, (byte) 0xcc, (byte) 0x36, (byte) 0x9c, (byte) 0xba, (byte) 0x8e,
            (byte) 0xbb, (byte) 0x26, (byte) 0x0e, (byte) 0xe6, (byte) 0xb6, (byte) 0xa1, (byte) 0x26, (byte) 0xd9,
            (byte) 0x34, (byte) 0x6e, (byte) 0x38, (byte) 0xc5, (byte) 0x02, (byte) 0x40, (byte) 0x67, (byte) 0x84,
            (byte) 0x71, (byte) 0xb2, (byte) 0x7a, (byte) 0x9c, (byte) 0xf4, (byte) 0x4e, (byte) 0xe9, (byte) 0x1a,
            (byte) 0x49, (byte) 0xc5, (byte) 0x14, (byte) 0x7d, (byte) 0xb1, (byte) 0xa9, (byte) 0xaa, (byte) 0xf2,
            (byte) 0x44, (byte) 0xf0, (byte) 0x5a, (byte) 0x43, (byte) 0x4d, (byte) 0x64, (byte) 0x86, (byte) 0x93,
            (byte) 0x1d, (byte) 0x2d, (byte) 0x14, (byte) 0x27, (byte) 0x1b, (byte) 0x9e, (byte) 0x35, (byte) 0x03,
            (byte) 0x0b, (byte) 0x71, (byte) 0xfd, (byte) 0x73, (byte) 0xda, (byte) 0x17, (byte) 0x90, (byte) 0x69,
            (byte) 0xb3, (byte) 0x2e, (byte) 0x29, (byte) 0x35, (byte) 0x63, (byte) 0x0e, (byte) 0x1c, (byte) 0x20,
            (byte) 0x62, (byte) 0x35, (byte) 0x4d, (byte) 0x0d, (byte) 0xa2, (byte) 0x0a, (byte) 0x6c, (byte) 0x41,
            (byte) 0x6e, (byte) 0x50, (byte) 0xbe, (byte) 0x79, (byte) 0x4c, (byte) 0xa4, (byte) 0x04, (byte) 0x16,
            (byte) 0x02, (byte) 0x14, (byte) 0x4f, (byte) 0xcf, (byte) 0x8c, (byte) 0xb3, (byte) 0x2a, (byte) 0x0f,
            (byte) 0xd6, (byte) 0x8a, (byte) 0xf8, (byte) 0x17, (byte) 0x0d, (byte) 0xf1, (byte) 0xce, (byte) 0xb8,
            (byte) 0x9d, (byte) 0x98, (byte) 0x62, (byte) 0x1b, (byte) 0xad, (byte) 0xec};

    /*
     * Used to test key (un)wrapping of a private key; assumes test vector #3
     * key and nonce.
     */
    private static final byte[] DSA_WRAPPED_PRIVATE_KEY = new byte[] {(byte) 0x14, (byte) 0xa8, (byte) 0x8d,
            (byte) 0xd7, (byte) 0x89, (byte) 0xea, (byte) 0x6d, (byte) 0x34, (byte) 0xd5, (byte) 0xd4, (byte) 0xd2,
            (byte) 0x10, (byte) 0x61, (byte) 0x36, (byte) 0x90, (byte) 0x40, (byte) 0x1e, (byte) 0x09, (byte) 0xd9,
            (byte) 0x59, (byte) 0x0e, (byte) 0xb8, (byte) 0xc4, (byte) 0xa1, (byte) 0x4a, (byte) 0x4e, (byte) 0x5e,
            (byte) 0x78, (byte) 0x06, (byte) 0xb6, (byte) 0x20, (byte) 0xae, (byte) 0xb0, (byte) 0xd3, (byte) 0xb8,
            (byte) 0xbf, (byte) 0xc7, (byte) 0x85, (byte) 0x76, (byte) 0xf1, (byte) 0x80, (byte) 0x9e, (byte) 0x5d,
            (byte) 0xe1, (byte) 0xb8, (byte) 0x7f, (byte) 0xd9, (byte) 0xe5, (byte) 0x61, (byte) 0x74, (byte) 0x7f,
            (byte) 0x29, (byte) 0x89, (byte) 0x26, (byte) 0x64, (byte) 0x13, (byte) 0xef, (byte) 0x03, (byte) 0x5c,
            (byte) 0x28, (byte) 0xf1, (byte) 0x49, (byte) 0xbb, (byte) 0xc6, (byte) 0xf5, (byte) 0xc8, (byte) 0x0b,
            (byte) 0x9f, (byte) 0x88, (byte) 0x14, (byte) 0xd1, (byte) 0x97, (byte) 0x1f, (byte) 0xad, (byte) 0x6b,
            (byte) 0x63, (byte) 0x38, (byte) 0x11, (byte) 0xbe, (byte) 0xcf, (byte) 0x09, (byte) 0x2d, (byte) 0x0a,
            (byte) 0xcd, (byte) 0xa4, (byte) 0x21, (byte) 0x66, (byte) 0x4f, (byte) 0x08, (byte) 0x55, (byte) 0x57,
            (byte) 0x4f, (byte) 0x06, (byte) 0x2b, (byte) 0xa9, (byte) 0x22, (byte) 0x6c, (byte) 0x28, (byte) 0x08,
            (byte) 0x2c, (byte) 0xf2, (byte) 0x43, (byte) 0x0c, (byte) 0x79, (byte) 0x93, (byte) 0xe5, (byte) 0x44,
            (byte) 0xbe, (byte) 0xa6, (byte) 0x20, (byte) 0x0a, (byte) 0xfc, (byte) 0xa0, (byte) 0x32, (byte) 0x3d,
            (byte) 0x9e, (byte) 0xe6, (byte) 0x52, (byte) 0x08, (byte) 0xce, (byte) 0xf3, (byte) 0xdf, (byte) 0x06,
            (byte) 0xd7, (byte) 0x31, (byte) 0x4f, (byte) 0x0a, (byte) 0xdd, (byte) 0x85, (byte) 0xd2, (byte) 0xa4,
            (byte) 0xea, (byte) 0xdb, (byte) 0x20, (byte) 0xe9, (byte) 0x0d, (byte) 0xb2, (byte) 0x28, (byte) 0x05,
            (byte) 0x80, (byte) 0xdd, (byte) 0x68, (byte) 0x6c, (byte) 0xbf, (byte) 0xcf, (byte) 0x7d, (byte) 0xd2,
            (byte) 0x9e, (byte) 0xc2, (byte) 0x54, (byte) 0x81, (byte) 0xd7, (byte) 0x8e, (byte) 0xf8, (byte) 0x6a,
            (byte) 0x3b, (byte) 0xb5, (byte) 0xee, (byte) 0xcc, (byte) 0x1a, (byte) 0x15, (byte) 0xf0, (byte) 0x95,
            (byte) 0x39, (byte) 0xdd, (byte) 0x54, (byte) 0xc6, (byte) 0x78, (byte) 0x5e, (byte) 0xae, (byte) 0x85,
            (byte) 0x3a, (byte) 0x7e, (byte) 0x2f, (byte) 0xc9, (byte) 0x00, (byte) 0xb8, (byte) 0xc8, (byte) 0xd3,
            (byte) 0x32, (byte) 0x7c, (byte) 0x5d, (byte) 0x9a, (byte) 0x6b, (byte) 0x6a, (byte) 0xb8, (byte) 0x22,
            (byte) 0x49, (byte) 0x3e, (byte) 0xff, (byte) 0x57, (byte) 0xc5, (byte) 0xe4, (byte) 0x8e, (byte) 0x8d,
            (byte) 0xbf, (byte) 0x67, (byte) 0xa4, (byte) 0xd9, (byte) 0x62, (byte) 0x0c};

    /*
     * Used to test key (un)wrapping of a private key; assumes test vector #3
     * key and nonce.
     */
    private static final byte[] DSA_WRAPPED_PRIVATE_KEY_MAC = new byte[] {(byte) 0xd9, (byte) 0xc1, (byte) 0x8c,
            (byte) 0xf8, (byte) 0x3a, (byte) 0xce, (byte) 0xc7, (byte) 0x9c, (byte) 0x07, (byte) 0x48, (byte) 0xa9,
            (byte) 0x13, (byte) 0x1e, (byte) 0x42, (byte) 0xaf, (byte) 0xf9};

    /* Used to test key (un)wrapping of a secret key. */
    private static final byte[] BLOWFISH_SECRET_KEY_MATERIAL = new byte[] {(byte) 0x94, (byte) 0xd7, (byte) 0x08,
            (byte) 0xff, (byte) 0xc3, (byte) 0x44, (byte) 0x38, (byte) 0x7a, (byte) 0xca, (byte) 0x40, (byte) 0xe7,
            (byte) 0xf3, (byte) 0xa1, (byte) 0xdf, (byte) 0x87, (byte) 0x9a, (byte) 0xc5, (byte) 0xcc, (byte) 0x63,
            (byte) 0x35, (byte) 0x28, (byte) 0xc8, (byte) 0x7e, (byte) 0x78, (byte) 0xd1, (byte) 0x81, (byte) 0x0d,
            (byte) 0x55, (byte) 0x77, (byte) 0xfd, (byte) 0x8a, (byte) 0x1d};

    /*
     * Used to test key (un)wrapping of a secret key; assumes test vector #3 key
     * and nonce.
     */
    private static final byte[] BLOWFISH_WRAPPED_SECRET_KEY = new byte[] {(byte) 0xb0, (byte) 0xfe, (byte) 0x43,
            (byte) 0x2a, (byte) 0x7e, (byte) 0x75, (byte) 0xdc, (byte) 0x5a, (byte) 0xd5, (byte) 0xe6, (byte) 0x67,
            (byte) 0x84, (byte) 0xa5, (byte) 0xc8, (byte) 0x60, (byte) 0xe0, (byte) 0x90, (byte) 0xec, (byte) 0x2a,
            (byte) 0xa1, (byte) 0xad, (byte) 0x5b, (byte) 0xe4, (byte) 0xca, (byte) 0x74, (byte) 0xd8, (byte) 0x6a,
            (byte) 0x99, (byte) 0x07, (byte) 0x3e, (byte) 0xbc, (byte) 0xf6};

    /*
     * Used to test key (un)wrapping of a secret key; assumes test vector #3 key
     * and nonce.
     */
    private static final byte[] BLOWFISH_WRAPPED_SECRET_KEY_MAC = new byte[] {(byte) 0x61, (byte) 0x44, (byte) 0xaa,
            (byte) 0xf9, (byte) 0xbb, (byte) 0x4d, (byte) 0xe6, (byte) 0x48, (byte) 0xc4, (byte) 0x1c, (byte) 0x9e,
            (byte) 0xd6, (byte) 0xb9, (byte) 0x30, (byte) 0xe1, (byte) 0x04};

    /*
     * The ASN.1 representation of a Helix test vector nonce and mac, used for
     * testing.
     */
    private static byte[] asn1NonceAndMac;

    /* A Helix secret key for testing. */
    private SecretKey secretKey;

    /* A HelixParameterSpec for testing encryption operations. */
    private AlgorithmParameterSpec encryptionParamSpec;

    /* A HelixParameterSpec for testing decryption operations. */
    private AlgorithmParameterSpec decryptionParamSpec;

    /* Helix algorithm parameters for testing encryption operations. */
    private AlgorithmParameters encryptionParameters;

    /* Helix algorithm parameters for testing decryption operations. */
    private AlgorithmParameters decryptionParameters;

    /* The Helix primitive used in unit tests. */
    private HelixCipher cipher;

    /* A CSPRNG used in some unit tests. */
    private SecureRandom secureRandom;

    /* A non-Helix key used in some unit tests. */
    private Key nonHelixKey;

    /* A non-secret key used in some unit tests. */
    private Key nonSecretKey;

    /**
     * Initializes the ASN.1 representation of a nonce and MAC using Helix test
     * vector #3.
     */
    @BeforeClass
    public static void initializeASN1NonceAndMac() {
        asn1NonceAndMac = new byte[38];
        asn1NonceAndMac[0] = 0x30; // Type=Sequence
        asn1NonceAndMac[1] = 0x24; // Length=36 (two OctetStrings)
        asn1NonceAndMac[2] = 0x04; // Type=OctetString
        asn1NonceAndMac[3] = 0x10; // Length=16
        System.arraycopy(TEST_VECTOR_3[NONCE], 0, asn1NonceAndMac, 4, 16); // Contents
        asn1NonceAndMac[20] = 0x04; // Type=OctetString
        asn1NonceAndMac[21] = 0x10; // Length=16
        System.arraycopy(TEST_VECTOR_3[MAC], 0, asn1NonceAndMac, 22, 16); // Contents
    }

    /**
     * Creates a number of support objects used in testing the operations of
     * {@link HelixCipher}.
     * 
     * @throws GeneralSecurityException
     *             if any support objects cannot be created
     */
    @Before
    public void createSupportObjects() throws GeneralSecurityException {
        secretKey = new SecretKeySpec(TEST_VECTOR_3[KEY], NinthTestProvider.HELIX);

        encryptionParamSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        decryptionParamSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);

        encryptionParameters =
                new AlgorithmParameters(new HelixAlgorithmParameters(), new NinthTestProvider(),
                        NinthTestProvider.HELIX) {
                    // nothing overridden here
                };
        encryptionParameters.init(encryptionParamSpec);

        decryptionParameters =
                new AlgorithmParameters(new HelixAlgorithmParameters(), new NinthTestProvider(),
                        NinthTestProvider.HELIX) {
                    // nothing overridden here
                };
        decryptionParameters.init(decryptionParamSpec);

        cipher = new HelixCipher();

        // use something non-default but generally available
        secureRandom = SecureRandom.getInstance("SHA1PRNG");

        nonHelixKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(new byte[8]));
        nonSecretKey =
                KeyFactory.getInstance("DH").generatePublic(
                        new DHPublicKeySpec(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO));
    }

    /**
     * Asserts that {@link HelixCipher#engineGetBlockSize()} returns zero.
     * 
     * <p>
     * The block size is zero because Helix is a stream cipher.
     * </p>
     */
    @Test
    public void engineGetBlockSizeReturnsZero() {
        assertEquals(0, cipher.engineGetBlockSize());
    }

    /**
     * Asserts that {@link HelixCipher#engineSetMode(String)} throws an
     * exception.
     * 
     * <p>
     * The Helix cipher does not support any explicit modes.
     * </p>
     * 
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testEngineSetMode_String() throws NoSuchAlgorithmException {
        cipher.engineSetMode("ECB");
    }

    /**
     * Asserts that {@link HelixCipher#engineSetPadding(String)} throws an
     * exception.
     * 
     * <p>
     * The Helix cipher does not support any explicit padding schemes.
     * </p>
     * 
     * @throws NoSuchPaddingException
     *             if the test fails
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testEngineSetPadding_String() throws NoSuchPaddingException {
        cipher.engineSetPadding("PKCS5Padding");
    }

    /* tests for HelixCipher#engineGetKeySize(Key) */

    /**
     * Asserts that {@link HelixCipher#engineGetKeySize(Key)} rejects a
     * <tt>null</tt> {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineGetKeySizeRejectsNullKey() throws InvalidKeyException {
        cipher.engineGetKeySize(null);
    }

    /**
     * Asserts that {@link HelixCipher#engineGetKeySize(Key)} rejects a
     * non-secret key.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineGetKeySizeRejectsNonSecretKey() throws InvalidKeyException {
        cipher.engineGetKeySize(nonSecretKey);
    }

    /**
     * Asserts that {@link HelixCipher#engineGetKeySize(Key)} rejects a
     * non-Helix key.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineGetKeySizeRejectsNonHelixKey() throws InvalidKeyException {
        cipher.engineGetKeySize(nonHelixKey);
    }

    /**
     * Asserts that {@link HelixCipher#engineGetKeySize(Key)} reports the
     * correct size for a Helix secret key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test
    public void engineGetKeySizeReportsCorrectSize() throws InvalidKeyException {
        int actualSize = cipher.engineGetKeySize(secretKey);

        // 40 = 5 * 8 = TEST_VECTOR_3[KEY].length * bits
        assertEquals(40, actualSize);
    }

    /* tests for HelixCipher#engineInit(int, Key, SecureRandom) */

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)} fails
     * if the operation mode is {@link Cipher#DECRYPT_MODE}.
     * 
     * <p>
     * A Helix cipher cannot be initialized for decryption without providing the
     * nonce.
     * </p>
     * 
     * @throws IllegalArgumentException
     *             if the test succeeds
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineInitForDecryptWithoutNonceFails() throws InvalidKeyException {
        // nonce is required for DECRYPT_MODE
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, null);
    }

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)} fails
     * if the operation mode is {@link Cipher#UNWRAP_MODE}.
     * 
     * <p>
     * A Helix cipher cannot be initialized for key unwrapping without providing
     * the nonce.
     * </p>
     * 
     * @throws IllegalArgumentException
     *             if the test succeeds
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineInitForUnwrapWithoutNonceFails() throws InvalidKeyException {
        // nonce is required for UNWRAP_MODE
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, null);
    }

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)}
     * rejects a <tt>null</tt> {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitRejectsNullKey() throws InvalidKeyException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, null, null);
    }

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)}
     * rejects a non-Helix {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitRejectsNonHelixKey() throws InvalidKeyException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, nonHelixKey, null);
    }

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)}
     * rejects a non-{@link SecretKey} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitRejectsNonSecretKey() throws InvalidKeyException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, nonSecretKey, null);
    }

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)}
     * accepts a <tt>null</tt> {@link SecureRandom} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsNullSecureRandom() throws InvalidKeyException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, null);
    }

    /**
     * Asserts that {@link HelixCipher#engineInit(int, Key, SecureRandom)}
     * accepts an explicit {@link SecureRandom} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsExplicitSecureRandom() throws InvalidKeyException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, secureRandom);
    }

    /*
     * tests for HelixCipher#engineInit(int, Key, AlgorithmParameterSpec,
     * SecureRandom)
     */

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a <tt>null</tt> {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitWithSpecRejectsNullKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, null, encryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a non-Helix {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitWithSpecRejectsNonHelixKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, nonHelixKey, encryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a non-{@link SecretKey} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitWithSpecRejectsNonSecretKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, nonSecretKey, encryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a <tt>null</tt> {@link AlgorithmParameterSpec} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitWithSpecRejectsNullSpec() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, (AlgorithmParameterSpec) null, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a non-Helix {@link AlgorithmParameterSpec} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitWithSpecRejectsNonHelixSpec() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, new PBEParameterSpec(new byte[8], 2048), null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * accepts a {@link HelixParameterSpec} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitWithSpecAcceptsHelixSpec() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a {@link HelixParameterSpec} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#ENCRYPT_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitForEncryptWithSpecRejectsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC should not be specified
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, decryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects a {@link HelixParameterSpec} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#WRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitForWrapWithSpecRejectsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC should not be specified
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, decryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * accepts a {@link HelixParameterSpec} argument with a <tt>null</tt> MAC
     * when the operation mode is {@link Cipher#DECRYPT_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForDecryptWithSpecAcceptsNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be bypassed
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, encryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects an {@link AlgorithmParameterSpec} argument that contains a MAC
     * with an incorrect length (!= 16) when initialized for decryption.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitForDecryptWithSpecRejectsMacWithBadLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16]) {
            @Override
            public byte[] getMac() {
                // bad length for MAC; not possible under normal usage
                return new byte[7];
            }
        };
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, spec, secureRandom);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * accepts a {@link HelixParameterSpec} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#DECRYPT_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForDecryptWithSpecAcceptsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be performed
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, decryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * accepts a {@link HelixParameterSpec} argument with a <tt>null</tt> MAC
     * when the operation mode is {@link Cipher#UNWRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForUnwrapWithSpecAcceptsNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be bypassed
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, encryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * rejects an {@link AlgorithmParameterSpec} argument that contains a MAC
     * with an incorrect length (!= 16) when initialized for key unwrapping.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitForUnwrapWithSpecRejectsMacWithBadLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16]) {
            @Override
            public byte[] getMac() {
                // bad length for MAC; not possible under normal usage
                return new byte[7];
            }
        };
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, spec, secureRandom);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * accepts a {@link HelixParameterSpec} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#UNWRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForUnwrapWithSpecAcceptsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be performed
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, decryptionParamSpec, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameterSpec, SecureRandom)}
     * accepts a {@link HelixParameterSpec} argument with a <tt>null</tt> MAC
     * when the operation mode is {@link Cipher#WRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForWrapWithSpecAcceptsNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, encryptionParamSpec, null);
    }

    /*
     * tests for HelixCipher#engineInit(int, Key, AlgorithmParameters,
     * SecureRandom)
     */

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects a <tt>null</tt> {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitWithParamsRejectsNullKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, null, encryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects a non-Helix {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitWithParamsRejectsNonHelixKey() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, nonHelixKey, encryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects a non-{@link SecretKey} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineInitWithParamsRejectsNonSecretKey() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, nonSecretKey, encryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects a <tt>null</tt> {@link AlgorithmParameters} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitWithParamsRejectsNullParams() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, (AlgorithmParameters) null, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects a non-Helix {@link AlgorithmParameters} argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitWithParamsRejectsNonHelixParams() throws InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, AlgorithmParameters.getInstance("AES"), null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects a {@link AlgorithmParameters} argument not provided by the
     * "NinthTest" provider.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitWithParamsRejectsNonNinthTestParams() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        @SuppressWarnings("serial")
        AlgorithmParameters notProvidedByNinthTest =
                new AlgorithmParameters(new HelixAlgorithmParameters(), new Provider(
                        "testEngineInit_Int_Key_AlgorithmParametersNotNinthTest_SecureRandom", 0,
                        "Not the NinthTest provider") {
                    // nothing overridden here
                }, NinthTestProvider.HELIX) {
                    // nothing overridden here
                };

        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, notProvidedByNinthTest, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects an {@link AlgorithmParameters} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#ENCRYPT_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitForEncryptWithParamsRejectsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC should not be specified
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, decryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * rejects an {@link AlgorithmParameters} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#WRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test succeeds
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void engineInitForWrapWithParamsRejectsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC should not be specified
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, decryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * accepts an {@link AlgorithmParameters} argument with a <tt>null</tt> MAC
     * when the operation mode is {@link Cipher#DECRYPT_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForDecryptWithParamsAcceptsNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be bypassed
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, encryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * accepts an {@link AlgorithmParameters} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#DECRYPT_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForDecryptWithParamsAcceptsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be performed
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, decryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * accepts an {@link AlgorithmParameters} argument with a <tt>null</tt> MAC
     * when the operation mode is {@link Cipher#UNWRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForUnwrapWithParamsAcceptsNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be bypassed
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, encryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * accepts an {@link AlgorithmParameters} argument with a non-<tt>null</tt>
     * MAC when the operation mode is {@link Cipher#UNWRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForUnwrapWithParamsAcceptsNonNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        // MAC verification would be performed
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, decryptionParameters, null);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineInit(int, Key, AlgorithmParameters, SecureRandom)}
     * accepts an {@link AlgorithmParameters} argument with a <tt>null</tt> MAC
     * when the operation mode is {@link Cipher#WRAP_MODE}.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineInitForWrapWithParamsAcceptsNullMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, encryptionParameters, null);
    }

    /* tests for HelixCipher#engineGetParameters() */

    /**
     * Asserts that {@link HelixCipher#engineGetParameters()} returns
     * <tt>null</tt> prior to cipher initialization.
     */
    @Test
    public void engineGetParametersBeforeEngineInit() {
        assertNull(cipher.engineGetParameters());
    }

    /**
     * Asserts that {@link HelixCipher#engineGetParameters()} returns the
     * expected parameters after cipher initialization.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineGetParametersAfterEngineInit() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IOException {
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, decryptionParameters, null);
        AlgorithmParameters params = cipher.engineGetParameters();

        assertArrayEquals(asn1NonceAndMac, params.getEncoded());
    }

    /**
     * Asserts that {@link HelixCipher#engineGetParameters()} returns the
     * expected parameters (specifically, the generated MAC) after a successful
     * encryption operation.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineGetParametersAfterEncryption() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);
        AlgorithmParameters params = cipher.engineGetParameters();

        assertArrayEquals(asn1NonceAndMac, params.getEncoded());
    }

    /* tests for HelixCipher#engineGetIV() */

    /**
     * Asserts that {@link HelixCipher#engineGetIV()} returns <tt>null</tt>
     * before cipher initialization.
     */
    @Test
    public void engineGetIVBeforeEngineInit() {
        assertNull(cipher.engineGetIV());
    }

    /**
     * Asserts that {@link HelixCipher#engineGetIV()} returns the expected nonce
     * after cipher initialization.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineGetIVAfterEngineInit() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);

        assertArrayEquals(TEST_VECTOR_3[NONCE], cipher.engineGetIV());
    }

    /* tests for HelixCipher#engineGetOutputSize(int) */

    /**
     * Asserts that {@link HelixCipher#engineGetOutputSize(int)} throws an
     * exception when the argument is less than zero.
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineGetOutputSizeLessThanZero() {
        cipher.engineGetOutputSize(-1);
    }

    /**
     * Asserts that {@link HelixCipher#engineGetOutputSize(int)} returns the
     * expected size before cipher initialization.
     */
    @Test
    public void engineGetOutputSizeBeforeEngineInit() {
        assertEquals(79, cipher.engineGetOutputSize(79));
    }

    /**
     * Asserts that {@link HelixCipher#engineGetOutputSize(int)} returns the
     * expected size <i>after</i> cipher initialization but <i>before</i> any
     * bytes are fed to the cipher.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineGetOutputSizeAfterEngineInit() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);

        assertEquals(79, cipher.engineGetOutputSize(79));
    }

    /**
     * Asserts that {@link HelixCipher#engineGetOutputSize(int)} returns the
     * expected size after some bytes have been fed to (and buffered by) the
     * cipher.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineGetOutputSizeWithBufferedBytes() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(TEST_VECTOR_3[PLAINTEXT], 0, 6); // process 4,
                                                             // buffer 2

        assertEquals(81, cipher.engineGetOutputSize(79));
    }

    /**
     * Asserts that {@link HelixCipher#engineGetOutputSize(int)} throws an
     * exception if an operation has been completed (and the cipher has not
     * since been re-initialized).
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalStateException.class)
    public void engineGetOutputSizeAfterCompletedOperation() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);

        cipher.engineGetOutputSize(79);
    }

    /* tests for HelixCipher#engineUpdate(byte[], int, int) */

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} rejects a
     * <tt>null</tt> input byte array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateRejectsNullInputByteArray() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(null, 0, 0);
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} fails if
     * the offset is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateInputOffsetLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[5], -1, 5);
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} fails if
     * the offset is greater than or equal to the input byte array length.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateInputOffsetGEByteArrayLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[5], 5, 5);
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} fails if
     * the length is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateInputLengthLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[5], 0, -1);
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} fails if
     * the offset and length do not represent a valid slice of the input byte
     * array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateWithBadInputOffsetAndLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[5], 2, 5);
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} returns
     * <tt>null</tt> if the input length is zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineUpdateInputLengthZero() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);

        assertNull(cipher.engineUpdate(new byte[5], 2, 0));
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} returns
     * the expected number of output bytes.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineUpdateExpectedBytes() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = cipher.engineUpdate(new byte[5], 0, 5); // buffers 1 byte

        assertEquals(4, out.length);
    }

    /**
     * Asserts that {@link HelixCipher#engineUpdate(byte[], int, int)} returns
     * <tt>null</tt> if the input (and any buffered bytes) represents less than
     * a whole number of words (32-bit integers).
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     */
    @Test
    public void engineUpdateNotEnoughForInputWord() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[5], 0, 5); // buffers 1 byte

        assertNull(cipher.engineUpdate(new byte[5], 0, 2));
    }

    /* tests for HelixCipher#engineUpdate(byte[], int, int, byte[], int) */

    /**
     * Asserts that
     * {@link HelixCipher#engineUpdate(byte[], int, int, byte[], int)} rejects a
     * <tt>null</tt> output byte array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateRejectsNullOutputByteArray() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[10], 0, 5, null, 0);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineUpdate(byte[], int, int, byte[], int)} fails if
     * the output offset is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateOutputOffsetLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[10], 0, 5, new byte[10], -1);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineUpdate(byte[], int, int, byte[], int)} fails if
     * the output offset is greater than or equal to the output byte array
     * length.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineUpdateOutputOffsetGEByteArrayLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[10], 0, 5, new byte[10], 10);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineUpdate(byte[], int, int, byte[], int)} returns
     * zero if the input length is zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     */
    @Test
    public void engineUpdateInputLengthZeroReturnsZero() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        int count = cipher.engineUpdate(new byte[10], 0, 0, new byte[10], 0);

        assertEquals(0, count);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineUpdate(byte[], int, int, byte[], int)} returns
     * zero if the input (and any buffered bytes) represents less than a whole
     * number of words (32-bit integers).
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     */
    @Test
    public void engineUpdateNotEnoughInputReturnsZero() throws InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = new byte[10];
        cipher.engineUpdate(new byte[10], 0, 5, out, 0); // buffers 1 byte
        int count = cipher.engineUpdate(new byte[10], 5, 2, out, 4);

        assertEquals(0, count);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineUpdate(byte[], int, int, byte[], int)} fails if
     * the processed bytes can't fit in the output byte array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test succeeds
     */
    @Test(expected = ShortBufferException.class)
    public void engineUpdateProcessedTooLargeForOutput() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = new byte[3];

        cipher.engineUpdate(new byte[10], 0, 5, out, 0);
    }

    /* tests for HelixCipher#engineDoFinal(byte[], int, int) */

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} rejects
     * a <tt>null</tt> input byte array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalRejectsNullInputByteArray() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(null, 0, 0);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} fails if
     * the offset is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalInputOffsetLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[5], -1, 5);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} fails if
     * the offset is greater than or equal to the input byte array length.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalInputOffsetGEByteArrayLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[5], 5, 5);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} fails if
     * the length is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalInputLengthLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[5], 0, -1);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} fails if
     * the offset and length do not represent a valid slice of the input byte
     * array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalWithBadInputOffsetAndLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[5], 2, 5);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} returns
     * an empty byte array if the input length is zero and there are no buffered
     * bytes.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test
    public void engineDoFinalInputLengthZeroNoBufferedBytes() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = cipher.engineDoFinal(new byte[5], 2, 0);

        assertArrayEquals(new byte[0], out);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} returns
     * the expected number of bytes if the input length is zero and there are
     * buffered bytes.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test
    public void engineDoFinalInputLengthZeroWithBufferedBytes() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineUpdate(new byte[5], 0, 3);
        byte[] out = cipher.engineDoFinal(new byte[5], 2, 0);

        assertEquals(3, out.length);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} returns
     * the expected number of output bytes.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test
    public void engineDoFinalExpectedBytes() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = cipher.engineDoFinal(new byte[5], 0, 5);

        assertEquals(5, out.length);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} updates
     * the parameters with the generated MAC after a successful encryption
     * operation.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineDoFinalUpdatesParamsWithGeneratedMac() throws InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
            InvalidParameterSpecException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);
        AlgorithmParameters params = cipher.engineGetParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_3[MAC], spec.getMac());
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} skips
     * MAC verification if the expected MAC is not provided when the cipher is
     * initialized for decryption.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test
    public void engineDoFinalSkipsMacVerification() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        HelixParameterSpec noMacVerifyParamSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, noMacVerifyParamSpec, null);
        /*
         * this would throw MessageAuthenticationException if MAC verification
         * occurred
         */
        cipher.engineDoFinal(new byte[11], 0, 11);
    }

    /**
     * Asserts that {@link HelixCipher#engineDoFinal(byte[], int, int)} raises
     * an exception if MAC verification fails.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = MessageAuthenticationException.class)
    public void engineDoFinalFailsMacVerification() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.DECRYPT_MODE, secretKey, decryptionParameters, null);
        cipher.engineDoFinal(new byte[11], 0, 11);
    }

    /* tests for HelixCipher#engineDoFinal(byte[], int, int, byte[], int) */

    /**
     * Asserts that
     * {@link HelixCipher#engineDoFinal(byte[], int, int, byte[], int)} rejects
     * a <tt>null</tt> output byte array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalRejectsNullOutputByteArray() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[10], 0, 5, null, 0);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineDoFinal(byte[], int, int, byte[], int)} fails if
     * the output offset is less than zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalOutputOffsetLTZero() throws InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[10], 0, 5, new byte[10], -1);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineDoFinal(byte[], int, int, byte[], int)} fails if
     * the output offset is greater than or equal to the output byte array
     * length.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = IllegalArgumentException.class)
    public void engineDoFinalOutputOffsetGEByteArrayLength() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        cipher.engineDoFinal(new byte[10], 0, 5, new byte[10], 10);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineDoFinal(byte[], int, int, byte[], int)} returns
     * zero if the input length is zero.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test
    public void engineDoFinalInputLengthZeroReturnsZero() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        int count = cipher.engineDoFinal(new byte[10], 0, 0, new byte[10], 0);

        assertEquals(0, count);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineDoFinal(byte[], int, int, byte[], int)} returns
     * zero if the input (and any buffered bytes) represents less than a whole
     * number of words (32-bit integers).
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test
    public void engineDoFinalNotEnoughInputReturnsZero() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = new byte[10];
        cipher.engineUpdate(new byte[10], 0, 5, out, 0); // buffers 1 byte
        int count = cipher.engineDoFinal(new byte[10], 5, 2, out, 4);

        assertEquals(3, count);
    }

    /**
     * Asserts that
     * {@link HelixCipher#engineDoFinal(byte[], int, int, byte[], int)} fails if
     * the processed bytes can't fit in the output byte array.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test succeeds
     * @throws BadPaddingException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = ShortBufferException.class)
    public void engineDoFinalProcessedTooLargeForOutput() throws InvalidKeyException,
            InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        cipher.engineInit(Cipher.ENCRYPT_MODE, secretKey, encryptionParameters, null);
        byte[] out = new byte[3];

        cipher.engineDoFinal(new byte[10], 0, 5, out, 0);
    }

    /*
     * full encryption/decryption tests
     * 
     * (NOTE: Helix test vector #1 cannot be used with HelixCipher or Cipher
     * because SecretKeySpec will not accept an empty byte array as key
     * material)
     */

    /**
     * Asserts that {@link HelixCipher} produces the expected ciphertext and MAC
     * when Helix test vector #2 plaintext is fed incrementally.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineUpdateEncryption2() throws InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        SecretKey key = new SecretKeySpec(TEST_VECTOR_2[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_2[NONCE]);
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, spec, null);

        byte[] cipherText = new byte[TEST_VECTOR_2[CIPHERTEXT].length];
        int count = cipher.engineUpdate(TEST_VECTOR_2[PLAINTEXT], 0, 8, cipherText, 0);
        count += cipher.engineUpdate(TEST_VECTOR_2[PLAINTEXT], 8, 8, cipherText, count);
        count += cipher.engineUpdate(TEST_VECTOR_2[PLAINTEXT], 16, 8, cipherText, count);
        cipher.engineDoFinal(TEST_VECTOR_2[PLAINTEXT], 24, 8, cipherText, count);

        AlgorithmParameters params = cipher.engineGetParameters();
        spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_2[CIPHERTEXT], cipherText);
        assertArrayEquals(TEST_VECTOR_2[MAC], spec.getMac());
    }

    /**
     * Asserts that {@link HelixCipher} produces the expected ciphertext and MAC
     * when Helix test vector #2 plaintext is fed incrementally.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineDoFinalEncryption2() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        SecretKey key = new SecretKeySpec(TEST_VECTOR_2[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_2[NONCE]);
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, spec, null);

        byte[] cipherText = cipher.engineDoFinal(TEST_VECTOR_2[PLAINTEXT], 0, TEST_VECTOR_2[PLAINTEXT].length);

        AlgorithmParameters params = cipher.engineGetParameters();
        spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_2[CIPHERTEXT], cipherText);
        assertArrayEquals(TEST_VECTOR_2[MAC], spec.getMac());
    }

    /**
     * Asserts that {@link HelixCipher} produces the expected ciphertext and MAC
     * when Helix test vector #3 plaintext is fed incrementally.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws ShortBufferException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineUpdateEncryption3() throws InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        SecretKey key = new SecretKeySpec(TEST_VECTOR_3[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, spec, null);

        byte[] cipherText = new byte[TEST_VECTOR_3[CIPHERTEXT].length];
        int count = cipher.engineUpdate(TEST_VECTOR_3[PLAINTEXT], 0, 10, cipherText, 0);
        cipher.engineDoFinal(TEST_VECTOR_3[PLAINTEXT], 10, 3, cipherText, count);

        AlgorithmParameters params = cipher.engineGetParameters();
        spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_3[CIPHERTEXT], cipherText);
        assertArrayEquals(TEST_VECTOR_3[MAC], spec.getMac());
    }

    /**
     * Asserts that {@link HelixCipher} produces the expected ciphertext and MAC
     * when Helix test vector #2 plaintext is fed incrementally.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws BadPaddingException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineDoFinalEncryption3() throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        SecretKey key = new SecretKeySpec(TEST_VECTOR_3[KEY], NinthTestProvider.HELIX);
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, spec, null);

        byte[] cipherText = cipher.engineDoFinal(TEST_VECTOR_3[PLAINTEXT], 0, TEST_VECTOR_3[PLAINTEXT].length);

        AlgorithmParameters params = cipher.engineGetParameters();
        spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_3[CIPHERTEXT], cipherText);
        assertArrayEquals(TEST_VECTOR_3[MAC], spec.getMac());
    }

    /* tests for HelixCipher#engineWrap(Key) */

    /**
     * Asserts that {@link HelixCipher#engineWrap(Key)} rejects a <tt>null</tt>
     * {@link Key} argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws IllegalBlockSizeException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineWrapRejectsNullKey() throws InvalidKeyException, IllegalBlockSizeException {
        cipher.engineWrap(null);
    }

    /**
     * Asserts that {@link HelixCipher#engineWrap(Key)} produces the expected
     * ciphertext and MAC for a wrapped public key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws InvalidKeySpecException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineWrapPublicKey() throws InvalidKeyException, InvalidAlgorithmParameterException,
            InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidParameterSpecException {
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, encryptionParameters, null);
        PublicKey dsaPublic =
                KeyFactory.getInstance("DSA").generatePublic(new X509EncodedKeySpec(DSA_PUBLIC_KEY_MATERIAL));
        byte[] wrappedKey = cipher.engineWrap(dsaPublic);
        AlgorithmParameters params = cipher.engineGetParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(DSA_WRAPPED_PUBLIC_KEY, wrappedKey);
        assertArrayEquals(DSA_WRAPPED_PUBLIC_KEY_MAC, spec.getMac());
    }

    /**
     * Asserts that {@link HelixCipher#engineWrap(Key)} produces the expected
     * ciphertext and MAC for a wrapped private key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws InvalidKeySpecException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineWrapPrivateKey() throws InvalidKeyException, InvalidAlgorithmParameterException,
            InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidParameterSpecException {
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, encryptionParameters, null);
        PrivateKey dsaPrivate =
                KeyFactory.getInstance("DSA").generatePrivate(new PKCS8EncodedKeySpec(DSA_PRIVATE_KEY_MATERIAL));
        byte[] wrappedKey = cipher.engineWrap(dsaPrivate);
        AlgorithmParameters params = cipher.engineGetParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(DSA_WRAPPED_PRIVATE_KEY, wrappedKey);
        assertArrayEquals(DSA_WRAPPED_PRIVATE_KEY_MAC, spec.getMac());
    }

    /**
     * Asserts that {@link HelixCipher#engineWrap(Key)} produces the expected
     * ciphertext and MAC for a wrapped secret key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws IllegalBlockSizeException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineWrapSecretKey() throws InvalidKeyException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidParameterSpecException {
        cipher.engineInit(Cipher.WRAP_MODE, secretKey, encryptionParameters, null);
        SecretKey blowfishSecret = new SecretKeySpec(BLOWFISH_SECRET_KEY_MATERIAL, "Blowfish");
        byte[] wrappedKey = cipher.engineWrap(blowfishSecret);
        AlgorithmParameters params = cipher.engineGetParameters();
        HelixParameterSpec spec = params.getParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(BLOWFISH_WRAPPED_SECRET_KEY, wrappedKey);
        assertArrayEquals(BLOWFISH_WRAPPED_SECRET_KEY_MAC, spec.getMac());
    }

    /* tests for HelixCipher#engineUnwrap(byte[], String, int) */

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)}
     * rejects a <tt>null</tt> byte array (wrapped key) argument.
     * 
     * @throws InvalidKeyException
     *             if the test succeeds
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test(expected = InvalidKeyException.class)
    public void engineUnwrapRejectsNullWrappedKey() throws InvalidKeyException, NoSuchAlgorithmException {
        cipher.engineUnwrap(null, "DSA", Cipher.PUBLIC_KEY);
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)}
     * rejects a <tt>null</tt> string (algorithm) argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test succeeds
     */
    @Test(expected = NoSuchAlgorithmException.class)
    public void engineUnwrapRejectsNullAlgorithm() throws InvalidKeyException, NoSuchAlgorithmException {
        cipher.engineUnwrap(new byte[0], null, Cipher.PRIVATE_KEY);
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)}
     * rejects an empty string (algorithm) argument.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test succeeds
     */
    @Test(expected = NoSuchAlgorithmException.class)
    public void engineUnwrapRejectsEmptyAlgorithm() throws InvalidKeyException, NoSuchAlgorithmException {
        cipher.engineUnwrap(new byte[0], "", Cipher.SECRET_KEY);
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)} passes
     * MAC verification and produces the expected plaintext for a wrapped public
     * key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test
    public void engineUnwrapPublicKey() throws InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], DSA_WRAPPED_PUBLIC_KEY_MAC);
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, spec, null);
        PublicKey dsaPublic = (PublicKey) cipher.engineUnwrap(DSA_WRAPPED_PUBLIC_KEY, "DSA", Cipher.PUBLIC_KEY);

        assertArrayEquals(DSA_PUBLIC_KEY_MATERIAL, dsaPublic.getEncoded());
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)} passes
     * MAC verification and produces the expected plaintext for a wrapped
     * private key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test
    public void engineUnwrapPrivateKey() throws InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], DSA_WRAPPED_PRIVATE_KEY_MAC);
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, spec, null);
        PrivateKey dsaPrivate = (PrivateKey) cipher.engineUnwrap(DSA_WRAPPED_PRIVATE_KEY, "DSA", Cipher.PRIVATE_KEY);

        assertArrayEquals(DSA_PRIVATE_KEY_MATERIAL, dsaPrivate.getEncoded());
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)} passes
     * MAC verification and produces the expected plaintext for a wrapped secret
     * key.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test
    public void engineUnwrapSecretKey() throws InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        HelixParameterSpec spec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], BLOWFISH_WRAPPED_SECRET_KEY_MAC);
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, spec, null);
        SecretKey blowfishSecret =
                (SecretKey) cipher.engineUnwrap(BLOWFISH_WRAPPED_SECRET_KEY, "Blowfish", Cipher.SECRET_KEY);

        assertArrayEquals(BLOWFISH_SECRET_KEY_MATERIAL, blowfishSecret.getEncoded());
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)} skips
     * MAC verification if a MAC is not provided at initialization.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test
    public void engineUnwrapSkipsMacVerification() throws InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16]);
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, spec, null);
        /*
         * the returned key is not be correct due to the wrong nonce; however,
         * this also means that MAC verification would fail if it was attempted
         */
        cipher.engineUnwrap(BLOWFISH_WRAPPED_SECRET_KEY, "Blowfish", Cipher.SECRET_KEY);
    }

    /**
     * Asserts that {@link HelixCipher#engineUnwrap(byte[], String, int)} throws
     * an exception when MAC verification fails.
     * 
     * @throws InvalidKeyException
     *             if the test fails
     * @throws InvalidAlgorithmParameterException
     *             if the test fails
     * @throws NoSuchAlgorithmException
     *             if the test fails
     */
    @Test(expected = MessageAuthenticationException.class)
    public void engineUnwrapFailsMacVerification() throws InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        HelixParameterSpec spec = new HelixParameterSpec(new byte[16], BLOWFISH_WRAPPED_SECRET_KEY_MAC);
        cipher.engineInit(Cipher.UNWRAP_MODE, secretKey, spec, null);
        /*
         * the returned key (and therefore the MAC) is not be correct due to the
         * wrong nonce
         */
        cipher.engineUnwrap(BLOWFISH_WRAPPED_SECRET_KEY, "Blowfish", Cipher.SECRET_KEY);
    }
}
