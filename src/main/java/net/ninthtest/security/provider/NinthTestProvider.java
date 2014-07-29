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

package net.ninthtest.security.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.AccessController;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import net.ninthtest.crypto.provider.helix.HelixAlgorithmParameters;
import net.ninthtest.crypto.provider.helix.HelixCipher;
import net.ninthtest.crypto.provider.helix.HelixKeyGenerator;
import net.ninthtest.crypto.provider.helix.HelixMac;
import net.ninthtest.crypto.provider.helix.HelixSecretKeyFactory;
import net.ninthtest.crypto.provider.helix.HelixSecureRandom;
import net.ninthtest.security.Messages;

/**
 * The NinthTest JCA Provider is a security service provider for the <a href=
 * "http://download.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html"
 * >Java Cryptography Architecture</a>.
 * 
 * <p>
 * The NinthTest JCA Provider focuses on supporting candidate, reference,
 * academic, and experimental cryptographic algorithms and security services.
 * </p>
 * 
 * <p style="color:red;font-weight:bold;">
 * Because the services provided by the NinthTest JCA Provider are
 * exploratory/provisional in nature, the NinthTest JCA Provider is not
 * recommended for use in security-critical applications or environments.
 * </p>
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 * @see <a href="http://www.ninthtest.net/java-security-provider">About the
 *      NinthTest JCA Provider</a>
 */
public final class NinthTestProvider extends Provider {
    /** The provider name. */
    public static final String NAME = "NinthTest";

    /**
     * The algorithm name for the Helix combined stream cipher and MAC function.
     */
    public static final String HELIX = "Helix";

    /** The provider version. */
    public static final double VERSION = 1.1;

    /** A short description of the provider. */
    public static final String INFO = "NinthTest provider v1.1 (Helix stream cipher with MAC function)";

    /* the universal serialization version ID for NinthTestProvider */
    private static final long serialVersionUID = 7121082131684638199L;

    /**
     * Verifies that the JAR containing this provider has not been tampered
     * with.
     * 
     * <p>
     * This method performs the following checks:
     * </p>
     * 
     * <ol>
     * <li>The provider JAR has been signed.</li>
     * <li>Each entry in the provider JAR is signed by a trusted signer.</li>
     * <li>The signature for each entry in the provider JAR was generated by the
     * same entity as the one that developed this provider.</li>
     * </ol>
     * 
     * <p>
     * If the self-integrity check fails for any reason, the runtime exception
     * {@link SecurityException} is thrown.
     * </p>
     */
    public static final synchronized void doSelfIntegrityCheck() {
        ProviderIntegrity.verify();
    }

    /**
     * Creates a new <tt>NinthTestProvider</tt> and initializes the set of
     * services provided.
     */
    public NinthTestProvider() {
        super(NAME, VERSION, INFO);

        /* Helix combined stream cipher and MAC function */
        putService(new Provider.Service(this, "Cipher", HELIX, HelixCipher.class.getName(), null, null));
        putService(new Provider.Service(this, "Mac", HELIX, HelixMac.class.getName(), null, null));
        putService(new Provider.Service(this, "SecureRandom", HELIX, HelixSecureRandom.class.getName(), null, null));
        putService(new Provider.Service(this, "SecretKeyFactory", HELIX, HelixSecretKeyFactory.class.getName(), null,
                null));
        putService(new Provider.Service(this, "AlgorithmParameters", HELIX, HelixAlgorithmParameters.class.getName(),
                null, null));
        putService(new Provider.Service(this, "KeyGenerator", HELIX, HelixKeyGenerator.class.getName(), null, null));
    }
}

/* Verifies the integrity of the signed provider JAR. */
final class ProviderIntegrity {
    /* raw bytes of the provider signing certificate */
    private static final byte[] PROVIDER_CERTIFICATE_BYTES = new byte[] {(byte) 0x30, (byte) 0x82, (byte) 0x03,
            (byte) 0xad, (byte) 0x30, (byte) 0x82, (byte) 0x03, (byte) 0x6b, (byte) 0xa0, (byte) 0x03, (byte) 0x02,
            (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x03, (byte) 0x34, (byte) 0x30, (byte) 0x0b,
            (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x38, (byte) 0x04,
            (byte) 0x03, (byte) 0x05, (byte) 0x00, (byte) 0x30, (byte) 0x81, (byte) 0x90, (byte) 0x31, (byte) 0x0b,
            (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13,
            (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x13, (byte) 0x02, (byte) 0x43, (byte) 0x41,
            (byte) 0x31, (byte) 0x12, (byte) 0x30, (byte) 0x10, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x07, (byte) 0x13, (byte) 0x09, (byte) 0x50, (byte) 0x61, (byte) 0x6c, (byte) 0x6f, (byte) 0x20,
            (byte) 0x41, (byte) 0x6c, (byte) 0x74, (byte) 0x6f, (byte) 0x31, (byte) 0x1d, (byte) 0x30, (byte) 0x1b,
            (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x14, (byte) 0x53,
            (byte) 0x75, (byte) 0x6e, (byte) 0x20, (byte) 0x4d, (byte) 0x69, (byte) 0x63, (byte) 0x72, (byte) 0x6f,
            (byte) 0x73, (byte) 0x79, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x6d, (byte) 0x73, (byte) 0x20,
            (byte) 0x49, (byte) 0x6e, (byte) 0x63, (byte) 0x31, (byte) 0x23, (byte) 0x30, (byte) 0x21, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x13, (byte) 0x1a, (byte) 0x4a, (byte) 0x61,
            (byte) 0x76, (byte) 0x61, (byte) 0x20, (byte) 0x53, (byte) 0x6f, (byte) 0x66, (byte) 0x74, (byte) 0x77,
            (byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20, (byte) 0x43, (byte) 0x6f, (byte) 0x64, (byte) 0x65,
            (byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x69, (byte) 0x6e, (byte) 0x67,
            (byte) 0x31, (byte) 0x1c, (byte) 0x30, (byte) 0x1a, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x03, (byte) 0x13, (byte) 0x13, (byte) 0x4a, (byte) 0x43, (byte) 0x45, (byte) 0x20, (byte) 0x43,
            (byte) 0x6f, (byte) 0x64, (byte) 0x65, (byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e,
            (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20, (byte) 0x43, (byte) 0x41, (byte) 0x30, (byte) 0x1e,
            (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0x31, (byte) 0x38,
            (byte) 0x32, (byte) 0x33, (byte) 0x35, (byte) 0x35, (byte) 0x31, (byte) 0x39, (byte) 0x5a, (byte) 0x17,
            (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x32, (byte) 0x32,
            (byte) 0x33, (byte) 0x35, (byte) 0x35, (byte) 0x31, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x5c,
            (byte) 0x31, (byte) 0x1d, (byte) 0x30, (byte) 0x1b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x0a, (byte) 0x13, (byte) 0x14, (byte) 0x53, (byte) 0x75, (byte) 0x6e, (byte) 0x20, (byte) 0x4d,
            (byte) 0x69, (byte) 0x63, (byte) 0x72, (byte) 0x6f, (byte) 0x73, (byte) 0x79, (byte) 0x73, (byte) 0x74,
            (byte) 0x65, (byte) 0x6d, (byte) 0x73, (byte) 0x20, (byte) 0x49, (byte) 0x6e, (byte) 0x63, (byte) 0x31,
            (byte) 0x23, (byte) 0x30, (byte) 0x21, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b,
            (byte) 0x13, (byte) 0x1a, (byte) 0x4a, (byte) 0x61, (byte) 0x76, (byte) 0x61, (byte) 0x20, (byte) 0x53,
            (byte) 0x6f, (byte) 0x66, (byte) 0x74, (byte) 0x77, (byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20,
            (byte) 0x43, (byte) 0x6f, (byte) 0x64, (byte) 0x65, (byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67,
            (byte) 0x6e, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x31, (byte) 0x16, (byte) 0x30, (byte) 0x14,
            (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x0d, (byte) 0x4e,
            (byte) 0x69, (byte) 0x6e, (byte) 0x74, (byte) 0x68, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x2e, (byte) 0x6e, (byte) 0x65, (byte) 0x74, (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0xb7,
            (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x2c, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48, (byte) 0xce, (byte) 0x38, (byte) 0x04, (byte) 0x01, (byte) 0x30, (byte) 0x82, (byte) 0x01,
            (byte) 0x1f, (byte) 0x02, (byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0xfd, (byte) 0x7f, (byte) 0x53,
            (byte) 0x81, (byte) 0x1d, (byte) 0x75, (byte) 0x12, (byte) 0x29, (byte) 0x52, (byte) 0xdf, (byte) 0x4a,
            (byte) 0x9c, (byte) 0x2e, (byte) 0xec, (byte) 0xe4, (byte) 0xe7, (byte) 0xf6, (byte) 0x11, (byte) 0xb7,
            (byte) 0x52, (byte) 0x3c, (byte) 0xef, (byte) 0x44, (byte) 0x00, (byte) 0xc3, (byte) 0x1e, (byte) 0x3f,
            (byte) 0x80, (byte) 0xb6, (byte) 0x51, (byte) 0x26, (byte) 0x69, (byte) 0x45, (byte) 0x5d, (byte) 0x40,
            (byte) 0x22, (byte) 0x51, (byte) 0xfb, (byte) 0x59, (byte) 0x3d, (byte) 0x8d, (byte) 0x58, (byte) 0xfa,
            (byte) 0xbf, (byte) 0xc5, (byte) 0xf5, (byte) 0xba, (byte) 0x30, (byte) 0xf6, (byte) 0xcb, (byte) 0x9b,
            (byte) 0x55, (byte) 0x6c, (byte) 0xd7, (byte) 0x81, (byte) 0x3b, (byte) 0x80, (byte) 0x1d, (byte) 0x34,
            (byte) 0x6f, (byte) 0xf2, (byte) 0x66, (byte) 0x60, (byte) 0xb7, (byte) 0x6b, (byte) 0x99, (byte) 0x50,
            (byte) 0xa5, (byte) 0xa4, (byte) 0x9f, (byte) 0x9f, (byte) 0xe8, (byte) 0x04, (byte) 0x7b, (byte) 0x10,
            (byte) 0x22, (byte) 0xc2, (byte) 0x4f, (byte) 0xbb, (byte) 0xa9, (byte) 0xd7, (byte) 0xfe, (byte) 0xb7,
            (byte) 0xc6, (byte) 0x1b, (byte) 0xf8, (byte) 0x3b, (byte) 0x57, (byte) 0xe7, (byte) 0xc6, (byte) 0xa8,
            (byte) 0xa6, (byte) 0x15, (byte) 0x0f, (byte) 0x04, (byte) 0xfb, (byte) 0x83, (byte) 0xf6, (byte) 0xd3,
            (byte) 0xc5, (byte) 0x1e, (byte) 0xc3, (byte) 0x02, (byte) 0x35, (byte) 0x54, (byte) 0x13, (byte) 0x5a,
            (byte) 0x16, (byte) 0x91, (byte) 0x32, (byte) 0xf6, (byte) 0x75, (byte) 0xf3, (byte) 0xae, (byte) 0x2b,
            (byte) 0x61, (byte) 0xd7, (byte) 0x2a, (byte) 0xef, (byte) 0xf2, (byte) 0x22, (byte) 0x03, (byte) 0x19,
            (byte) 0x9d, (byte) 0xd1, (byte) 0x48, (byte) 0x01, (byte) 0xc7, (byte) 0x02, (byte) 0x15, (byte) 0x00,
            (byte) 0x97, (byte) 0x60, (byte) 0x50, (byte) 0x8f, (byte) 0x15, (byte) 0x23, (byte) 0x0b, (byte) 0xcc,
            (byte) 0xb2, (byte) 0x92, (byte) 0xb9, (byte) 0x82, (byte) 0xa2, (byte) 0xeb, (byte) 0x84, (byte) 0x0b,
            (byte) 0xf0, (byte) 0x58, (byte) 0x1c, (byte) 0xf5, (byte) 0x02, (byte) 0x81, (byte) 0x81, (byte) 0x00,
            (byte) 0xf7, (byte) 0xe1, (byte) 0xa0, (byte) 0x85, (byte) 0xd6, (byte) 0x9b, (byte) 0x3d, (byte) 0xde,
            (byte) 0xcb, (byte) 0xbc, (byte) 0xab, (byte) 0x5c, (byte) 0x36, (byte) 0xb8, (byte) 0x57, (byte) 0xb9,
            (byte) 0x79, (byte) 0x94, (byte) 0xaf, (byte) 0xbb, (byte) 0xfa, (byte) 0x3a, (byte) 0xea, (byte) 0x82,
            (byte) 0xf9, (byte) 0x57, (byte) 0x4c, (byte) 0x0b, (byte) 0x3d, (byte) 0x07, (byte) 0x82, (byte) 0x67,
            (byte) 0x51, (byte) 0x59, (byte) 0x57, (byte) 0x8e, (byte) 0xba, (byte) 0xd4, (byte) 0x59, (byte) 0x4f,
            (byte) 0xe6, (byte) 0x71, (byte) 0x07, (byte) 0x10, (byte) 0x81, (byte) 0x80, (byte) 0xb4, (byte) 0x49,
            (byte) 0x16, (byte) 0x71, (byte) 0x23, (byte) 0xe8, (byte) 0x4c, (byte) 0x28, (byte) 0x16, (byte) 0x13,
            (byte) 0xb7, (byte) 0xcf, (byte) 0x09, (byte) 0x32, (byte) 0x8c, (byte) 0xc8, (byte) 0xa6, (byte) 0xe1,
            (byte) 0x3c, (byte) 0x16, (byte) 0x7a, (byte) 0x8b, (byte) 0x54, (byte) 0x7c, (byte) 0x8d, (byte) 0x28,
            (byte) 0xe0, (byte) 0xa3, (byte) 0xae, (byte) 0x1e, (byte) 0x2b, (byte) 0xb3, (byte) 0xa6, (byte) 0x75,
            (byte) 0x91, (byte) 0x6e, (byte) 0xa3, (byte) 0x7f, (byte) 0x0b, (byte) 0xfa, (byte) 0x21, (byte) 0x35,
            (byte) 0x62, (byte) 0xf1, (byte) 0xfb, (byte) 0x62, (byte) 0x7a, (byte) 0x01, (byte) 0x24, (byte) 0x3b,
            (byte) 0xcc, (byte) 0xa4, (byte) 0xf1, (byte) 0xbe, (byte) 0xa8, (byte) 0x51, (byte) 0x90, (byte) 0x89,
            (byte) 0xa8, (byte) 0x83, (byte) 0xdf, (byte) 0xe1, (byte) 0x5a, (byte) 0xe5, (byte) 0x9f, (byte) 0x06,
            (byte) 0x92, (byte) 0x8b, (byte) 0x66, (byte) 0x5e, (byte) 0x80, (byte) 0x7b, (byte) 0x55, (byte) 0x25,
            (byte) 0x64, (byte) 0x01, (byte) 0x4c, (byte) 0x3b, (byte) 0xfe, (byte) 0xcf, (byte) 0x49, (byte) 0x2a,
            (byte) 0x03, (byte) 0x81, (byte) 0x84, (byte) 0x00, (byte) 0x02, (byte) 0x81, (byte) 0x80, (byte) 0x67,
            (byte) 0xaa, (byte) 0xea, (byte) 0xa7, (byte) 0x8f, (byte) 0xa5, (byte) 0x6b, (byte) 0xe6, (byte) 0xb8,
            (byte) 0x0f, (byte) 0x9b, (byte) 0xf6, (byte) 0x2f, (byte) 0xa3, (byte) 0xe4, (byte) 0x40, (byte) 0xc9,
            (byte) 0x6d, (byte) 0x0c, (byte) 0xf8, (byte) 0xd9, (byte) 0x84, (byte) 0xa9, (byte) 0xe0, (byte) 0x62,
            (byte) 0xba, (byte) 0x3a, (byte) 0xf0, (byte) 0xff, (byte) 0x33, (byte) 0x7b, (byte) 0xfd, (byte) 0x5e,
            (byte) 0xfd, (byte) 0xfa, (byte) 0x73, (byte) 0xf3, (byte) 0x92, (byte) 0xb2, (byte) 0xf6, (byte) 0x80,
            (byte) 0x8c, (byte) 0xf0, (byte) 0xdf, (byte) 0xde, (byte) 0x50, (byte) 0x18, (byte) 0xd4, (byte) 0x79,
            (byte) 0x2f, (byte) 0x13, (byte) 0xae, (byte) 0x1f, (byte) 0xcf, (byte) 0x24, (byte) 0x7c, (byte) 0x03,
            (byte) 0x82, (byte) 0x3b, (byte) 0xe7, (byte) 0xfd, (byte) 0xdb, (byte) 0x01, (byte) 0xba, (byte) 0x9a,
            (byte) 0x82, (byte) 0xcc, (byte) 0x74, (byte) 0xa5, (byte) 0xe2, (byte) 0xae, (byte) 0xa0, (byte) 0xbe,
            (byte) 0xfa, (byte) 0x0f, (byte) 0xd1, (byte) 0x17, (byte) 0xd4, (byte) 0x14, (byte) 0xae, (byte) 0x18,
            (byte) 0x24, (byte) 0x8a, (byte) 0xf9, (byte) 0xfe, (byte) 0x5b, (byte) 0x7c, (byte) 0x04, (byte) 0x7b,
            (byte) 0x61, (byte) 0xf2, (byte) 0x85, (byte) 0x0b, (byte) 0x1f, (byte) 0xdb, (byte) 0x33, (byte) 0xcb,
            (byte) 0xf5, (byte) 0x4d, (byte) 0xdd, (byte) 0xd4, (byte) 0xd6, (byte) 0x27, (byte) 0x50, (byte) 0xbf,
            (byte) 0x81, (byte) 0x31, (byte) 0xad, (byte) 0x76, (byte) 0x77, (byte) 0x59, (byte) 0x20, (byte) 0x4b,
            (byte) 0x30, (byte) 0xb8, (byte) 0x89, (byte) 0x36, (byte) 0x19, (byte) 0x6f, (byte) 0x55, (byte) 0xf2,
            (byte) 0x17, (byte) 0x23, (byte) 0x4e, (byte) 0x6a, (byte) 0xf2, (byte) 0xbb, (byte) 0x04, (byte) 0xa3,
            (byte) 0x81, (byte) 0x86, (byte) 0x30, (byte) 0x81, (byte) 0x83, (byte) 0x30, (byte) 0x11, (byte) 0x06,
            (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x86, (byte) 0xf8, (byte) 0x42,
            (byte) 0x01, (byte) 0x01, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x10,
            (byte) 0x30, (byte) 0x0e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01,
            (byte) 0x01, (byte) 0xff, (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x05, (byte) 0xe0,
            (byte) 0x30, (byte) 0x1d, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0e, (byte) 0x04,
            (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0x78, (byte) 0x40, (byte) 0x8f, (byte) 0xf0, (byte) 0xe5,
            (byte) 0xa4, (byte) 0xf3, (byte) 0x42, (byte) 0x8e, (byte) 0x0b, (byte) 0x6b, (byte) 0xa0, (byte) 0xbc,
            (byte) 0x38, (byte) 0x3e, (byte) 0x8b, (byte) 0xed, (byte) 0xb3, (byte) 0x49, (byte) 0x6b, (byte) 0x30,
            (byte) 0x1f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04, (byte) 0x18,
            (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x65, (byte) 0xe2, (byte) 0xf4, (byte) 0x86,
            (byte) 0xc9, (byte) 0xd3, (byte) 0x4e, (byte) 0xf0, (byte) 0x91, (byte) 0x4e, (byte) 0x58, (byte) 0xa2,
            (byte) 0x6a, (byte) 0xf5, (byte) 0xd8, (byte) 0x78, (byte) 0x5a, (byte) 0x9a, (byte) 0xc1, (byte) 0xa6,
            (byte) 0x30, (byte) 0x1e, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x11, (byte) 0x04,
            (byte) 0x17, (byte) 0x30, (byte) 0x15, (byte) 0x81, (byte) 0x13, (byte) 0x6d, (byte) 0x61, (byte) 0x74,
            (byte) 0x74, (byte) 0x7a, (byte) 0x40, (byte) 0x6e, (byte) 0x69, (byte) 0x6e, (byte) 0x74, (byte) 0x68,
            (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x2e, (byte) 0x6e, (byte) 0x65, (byte) 0x74,
            (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce,
            (byte) 0x38, (byte) 0x04, (byte) 0x03, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x2f, (byte) 0x00,
            (byte) 0x30, (byte) 0x2c, (byte) 0x02, (byte) 0x14, (byte) 0x64, (byte) 0xf7, (byte) 0x4e, (byte) 0x3e,
            (byte) 0x1e, (byte) 0x4e, (byte) 0xd9, (byte) 0xa3, (byte) 0x8d, (byte) 0xac, (byte) 0x67, (byte) 0xc4,
            (byte) 0x6b, (byte) 0xee, (byte) 0x19, (byte) 0xa2, (byte) 0xc7, (byte) 0xc2, (byte) 0x01, (byte) 0x31,
            (byte) 0x02, (byte) 0x14, (byte) 0x21, (byte) 0x09, (byte) 0xe0, (byte) 0x68, (byte) 0xa6, (byte) 0x58,
            (byte) 0x6e, (byte) 0x13, (byte) 0xe4, (byte) 0x81, (byte) 0xd0, (byte) 0x66, (byte) 0x76, (byte) 0x7b,
            (byte) 0x9b, (byte) 0x8d, (byte) 0x4b, (byte) 0x96, (byte) 0x94, (byte) 0x6c};

    /* created from PROVIDER_CERTIFICATE_BYTES */
    private static X509Certificate providerCertificate;

    /*
     * indicates whether or not the self-integrity check has passed
     * 
     * doSelfIntegrityCheck() will set this flag to true if the self-integrity
     * check passes (avoids redundant checks)
     */
    // UNITTESTING: Set to true for unit testing.
    private static boolean selfIntegrityVerified = true;

    /*
     * Verifies that the JAR containing this provider has not been tampered
     * with.
     * 
     * 1. The provider JAR has been signed. 2. Each entry in the provider JAR is
     * signed by a trusted signer. 3. The signature for each entry in the
     * provider JAR was generated by the same entity as the one that developed
     * this provider.
     * 
     * If the self-integrity check fails for any reason, SecurityException is
     * thrown.
     */
    static final synchronized void verify() {
        /* avoid redundant self-integrity checks */
        if (selfIntegrityVerified) {
            return;
        }

        JarInputStream providerJar = null;
        try {
            providerJar = getProviderJarInputStream();
            /*
             * "early warning" - this will fail if ANY part of the signed JAR
             * has been tampered with; however, it will pass silently if the JAR
             * is NOT signed, so further checking is necessary
             */
            if (providerJar.getManifest() == null) {
                throw new SecurityException(Messages.getMessage("error.not_signed"));
            }

            /* verify each JAR entry */
            if (providerCertificate == null) {
                providerCertificate = getProviderCert();
            }
            JarEntry entry = null;
            byte[] buffer = new byte[8192];
            boolean signedByProviderCert = false;
            while ((entry = providerJar.getNextJarEntry()) != null) {
                if (entry.isDirectory() || entry.getName().startsWith("META-INF/")) {
                    continue;
                }

                /*
                 * reading each entry will perform signature & digest
                 * verification
                 */
                while (providerJar.read(buffer) != -1) {
                    // do nothing - only need to read the bytes
                }

                /*
                 * also need to ensure that each entry was signed by the
                 * provider signing certificate; getCodeSigners() can only be
                 * called once the entry has been completely verified by reading
                 * from the entry input stream!
                 */
                signedByProviderCert = false;
                for (CodeSigner signer : entry.getCodeSigners()) {
                    if (signedByProviderCert =
                            providerCertificate.equals(signer.getSignerCertPath().getCertificates().get(0))) {
                        break;
                    }
                }

                if (!signedByProviderCert) {
                    throw new SecurityException(Messages.getMessage("error.not_signed_by_trusted"));
                }
            }
        } catch (Exception ex) {
            throw new SecurityException(Messages.getMessage("error.integrity_not_verified"), ex);
        } finally {
            if (providerJar != null) {
                try {
                    providerJar.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }

        /* avoid redundant integrity checking */
        selfIntegrityVerified = true;
    }

    /*
     * Returns an input stream to read the contents of the provider JAR.
     * 
     * The caller is responsible for closing this input stream!
     */
    private static JarInputStream getProviderJarInputStream() throws PrivilegedActionException {
        JarInputStream jarInputStream = AccessController.doPrivileged(new PrivilegedExceptionAction<JarInputStream>() {
            @Override
            public JarInputStream run() throws Exception {
                CodeSource codeSource = NinthTestProvider.class.getProtectionDomain().getCodeSource();
                URL location = codeSource.getLocation();
                if (location == null) {
                    return null;
                }

                return new JarInputStream(location.openStream(), true);
            }
        });

        return jarInputStream;
    }

    /*
     * Generates the provider signing certificate.
     */
    private static X509Certificate getProviderCert() throws CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream byteStream = new ByteArrayInputStream(PROVIDER_CERTIFICATE_BYTES);
        X509Certificate x509 = (X509Certificate) cf.generateCertificate(byteStream);
        byteStream.close();
        return x509;
    }

    private ProviderIntegrity() {
        /* never instantiated */
    }
}
