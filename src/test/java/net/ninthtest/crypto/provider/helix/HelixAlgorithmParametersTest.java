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
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.RC2ParameterSpec;

import net.ninthtest.crypto.helix.HelixTestVectors;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * The unit test case for {@link HelixAlgorithmParameters}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixAlgorithmParametersTest implements HelixTestVectors {
    /*
     * Expected string representation of a HelixAlgorithmParameters initialized
     * with a nonce.
     */
    private static final String TOSTRING_TEST_VECTOR_3_NONCE_ONLY =
            "helixParameters HelixNonce ::= {\"30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66\"}";

    /*
     * Expected string representation of a HelixAlgorithmParameters initialized
     * with a nonce and MAC.
     */
    private static final String TOSTRING_TEST_VECTOR_3_NONCE_AND_MAC =
            "helixParameters HelixNonceAndMac ::= {\n    nonce  \"30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66\",\n    mac    \"6c 82 d1 aa 3b 90 5f 12 f1 44 3f a7 f6 a1 01 d2\"\n}";

    /* The ASN.1 representation of the Helix test vector #3 nonce. */
    private static byte[] asn1Nonce;

    /* The ASN.1 representation of the Helix test vector #3 nonce and MAC. */
    private static byte[] asn1NonceAndMac;

    /* An ASN.1 representation that specifies an unrecognized type. */
    private static byte[] asn1BadType;

    /* An ASN.1 representation of a nonce that specifies an incorrect length. */
    private static byte[] asn1NonceBadLength;

    /*
     * An ASN.1 representation of a nonce and MAC that specifies an incorrect
     * length.
     */
    private static byte[] asn1SequenceBadLength;

    /*
     * An ASN.1 representation of a nonce and MAC that specifies an unrecognized
     * type for the nonce.
     */
    private static byte[] asn1SequenceNonceBadType;

    /*
     * An ASN.1 representation of a nonce and MAC that specifies an incorrect
     * length for the nonce.
     */
    private static byte[] asn1SequenceNonceBadLength;

    /*
     * An ASN.1 representation of a nonce and MAC that specifies an unrecognized
     * type for the MAC.
     */
    private static byte[] asn1SequenceMacBadType;

    /*
     * An ASN.1 representation of a nonce and MAC that specifies an incorrect
     * length for the MAC.
     */
    private static byte[] asn1SequenceMacBadLength;

    /* The instance used by test fixtures. */
    private HelixAlgorithmParameters parameters;

    /**
     * Initializes the <i>ASN.1</i> structures used for testing.
     */
    @BeforeClass
    public static void initializeASN1ByteArrays() {
        asn1Nonce = new byte[18];
        asn1Nonce[0] = 0x04; // Type=OctetString
        asn1Nonce[1] = 0x10; // Length=16
        System.arraycopy(TEST_VECTOR_3[NONCE], 0, asn1Nonce, 2, 16); // Contents

        asn1NonceAndMac = new byte[38];
        asn1NonceAndMac[0] = 0x30; // Type=Sequence
        asn1NonceAndMac[1] = 0x24; // Length=36 (two OctetStrings)
        asn1NonceAndMac[2] = 0x04; // Type=OctetString
        asn1NonceAndMac[3] = 0x10; // Length=16
        System.arraycopy(TEST_VECTOR_3[NONCE], 0, asn1NonceAndMac, 4, 16); // Contents
        asn1NonceAndMac[20] = 0x04; // Type=OctetString
        asn1NonceAndMac[21] = 0x10; // Length=16
        System.arraycopy(TEST_VECTOR_3[MAC], 0, asn1NonceAndMac, 22, 16); // Contents

        asn1BadType = new byte[18];
        System.arraycopy(asn1Nonce, 0, asn1BadType, 0, 18);
        asn1BadType[0] = 0x16; // Type=IA5String

        asn1NonceBadLength = new byte[18];
        System.arraycopy(asn1Nonce, 0, asn1NonceBadLength, 0, 18);
        asn1NonceBadLength[1] = 0x11; // Length=17

        asn1SequenceBadLength = new byte[38];
        System.arraycopy(asn1NonceAndMac, 0, asn1SequenceBadLength, 0, 38);
        asn1SequenceBadLength[1] = 0x25; // Length=37

        asn1SequenceNonceBadType = new byte[38];
        System.arraycopy(asn1NonceAndMac, 0, asn1SequenceNonceBadType, 0, 38);
        asn1SequenceNonceBadType[2] = 0x16; // Type=IA5String

        asn1SequenceNonceBadLength = new byte[38];
        System.arraycopy(asn1NonceAndMac, 0, asn1SequenceNonceBadLength, 0, 38);
        asn1SequenceNonceBadLength[3] = 0x11; // Length=17

        asn1SequenceMacBadType = new byte[38];
        System.arraycopy(asn1NonceAndMac, 0, asn1SequenceMacBadType, 0, 38);
        asn1SequenceMacBadType[20] = 0x16; // Type=IA5String

        asn1SequenceMacBadLength = new byte[38];
        System.arraycopy(asn1NonceAndMac, 0, asn1SequenceMacBadLength, 0, 38);
        asn1SequenceMacBadLength[21] = 0x11; // Length=17
    }

    /**
     * Creates an instance of {@link HelixAlgorithmParameters} for testing.
     */
    @Before
    public void createHelixAlgorithmParameters() {
        parameters = new HelixAlgorithmParameters();
    }

    /* tests for HelixAlgorithmParameters#engineInit(AlgorithmParameterSpec) */

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineInit(AlgorithmParameterSpec)}
     * rejects a <tt>null</tt> argument.
     * 
     * @throws InvalidParameterSpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidParameterSpecException.class)
    public void engineInitRejectsNullSpec() throws InvalidParameterSpecException {
        AlgorithmParameterSpec paramSpec = null;
        parameters.engineInit(paramSpec);
    }

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineInit(AlgorithmParameterSpec)}
     * rejects a non-<tt>null</tt> argument that is <i>not</i> a
     * {@link HelixParameterSpec}.
     * 
     * @throws InvalidParameterSpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidParameterSpecException.class)
    public void engineInitRejectsNonHelixSpec() throws InvalidParameterSpecException {
        AlgorithmParameterSpec paramSpec = new RC2ParameterSpec(0);
        parameters.engineInit(paramSpec);
    }

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineInit(AlgorithmParameterSpec)}
     * accepts a {@link HelixParameterSpec} that specifies only a nonce.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsSpecWithNonceOnly() throws InvalidParameterSpecException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        parameters.engineInit(paramSpec);
    }

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineInit(AlgorithmParameterSpec)}
     * accepts a {@link HelixParameterSpec} that specifies a nonce and MAC.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsSpecWithNonceAndMac() throws InvalidParameterSpecException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        parameters.engineInit(paramSpec);
    }

    /* tests for HelixAlgorithmParameters#engineInit(byte[]) */

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a <tt>null</tt> byte array.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsNullByteArray() throws IOException {
        byte[] params = null;

        parameters.engineInit(params);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that does not have an acceptable length.
     * 
     * <p>
     * The acceptable lengths are 18 (for a nonce-only byte array) or 38 (for a
     * nonce and MAC byte array).
     * </p>
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsByteArrayWithBadLength() throws IOException {
        // should be length 18 or 38
        byte[] params = new byte[28];
        parameters.engineInit(params);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an unrecognized ASN.1 type.
     * 
     * <p>
     * The recognized ASN.1 types are <tt>0x04</tt> (<i>OctetString</i>) or
     * <tt>0x30</tt> (<i>Sequence</i>).
     * </p>
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsByteArrayWithBadASN1Type() throws IOException {
        parameters.engineInit(asn1BadType);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an incorrect length for the nonce.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsByteArrayWithBadNonceLength() throws IOException {
        parameters.engineInit(asn1NonceBadLength);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an incorrect length for the sequence
     * containing the nonce and MAC.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsSequenceWithBadLength() throws IOException {
        parameters.engineInit(asn1SequenceBadLength);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an incorrect type for the nonce in a
     * sequence.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsSequenceWithBadNonceType() throws IOException {
        parameters.engineInit(asn1SequenceNonceBadType);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an incorrect length for the nonce in a
     * sequence.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsSequenceWithBadNonceLength() throws IOException {
        parameters.engineInit(asn1SequenceNonceBadLength);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an incorrect type for the MAC in a sequence.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsSequenceWithBadMacType() throws IOException {
        parameters.engineInit(asn1SequenceMacBadType);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} rejects
     * a byte array that specifies an incorrect length for the MAC in a
     * sequence.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsSequenceWithBadMacLength() throws IOException {
        parameters.engineInit(asn1SequenceMacBadLength);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} accepts
     * a byte array containing only a nonce.
     * 
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsASN1NonceOnly() throws IOException {
        parameters.engineInit(asn1Nonce);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[])} accepts
     * a byte array containing a nonce and a MAC.
     * 
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsASN1NonceAndMac() throws IOException {
        parameters.engineInit(asn1NonceAndMac);
    }

    /* tests for HelixAlgorithmParameters#engineInit(byte[], String) */

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[], String)}
     * rejects a byte array that does not represent an ASN.1 nonce or nonce+MAC
     * sequence.
     * 
     * @throws IOException
     *             if the test succeeds
     */
    @Test(expected = IOException.class)
    public void engineInitRejectsNonASN1WithUnrecognizedFormat() throws IOException {
        parameters.engineInit(TEST_VECTOR_3[NONCE], "FAIL");
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[], String)}
     * accepts a correctly-formatted ASN.1 byte array when the format is
     * <tt>null</tt>.
     * 
     * <p>
     * A <tt>null</tt> format indicates that the primary decoding format (ASN.1)
     * should be assumed.
     * </p>
     * 
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsASN1WithNullFormat() throws IOException {
        parameters.engineInit(asn1NonceAndMac, null);
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[], String)}
     * accepts a correctly-formatted ASN.1 byte array when the format is
     * "ASN.1".
     * 
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsASN1WithASN1Format() throws IOException {
        parameters.engineInit(asn1NonceAndMac, "ASN.1");
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[], String)}
     * accepts a correctly-formatted ASN.1 byte array when the format is "DER".
     * 
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsASN1WithDERFormat() throws IOException {
        parameters.engineInit(asn1NonceAndMac, "DER");
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineInit(byte[], String)}
     * accepts a correctly-formatted ASN.1 byte array even when the format is
     * not recognized.
     * 
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineInitAcceptsASN1WithUnrecognizedFormat() throws IOException {
        parameters.engineInit(asn1NonceAndMac, "OKAY");
    }

    /* tests for HelixAlgorithmParameters#engineGetParameterSpec(Class) */

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineGetParameterSpec(Class)} rejects a
     * <tt>null</tt> class argument.
     * 
     * @throws InvalidParameterSpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidParameterSpecException.class)
    public void engineGetParameterSpecRejectsNullClass() throws InvalidParameterSpecException {
        parameters.engineGetParameterSpec(null);
    }

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineGetParameterSpec(Class)} rejects a
     * class that is not {@link HelixParameterSpec}.
     * 
     * @throws InvalidParameterSpecException
     *             if the test succeeds
     */
    @Test(expected = InvalidParameterSpecException.class)
    public void engineGetParameterSpecRejectsNonHelixClass() throws InvalidParameterSpecException {
        parameters.engineGetParameterSpec(RC2ParameterSpec.class);
    }

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineGetParameterSpec(Class)} creates a
     * {@link HelixParameterSpec} with a nonce only.
     * 
     * @throws IOException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineGetParameterSpecForNonceOnly() throws IOException, InvalidParameterSpecException {
        parameters.engineInit(asn1Nonce);
        HelixParameterSpec paramSpec = parameters.engineGetParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_3[NONCE], paramSpec.getNonce());
        assertNull(paramSpec.getMac());
    }

    /**
     * Asserts that
     * {@link HelixAlgorithmParameters#engineGetParameterSpec(Class)} creates a
     * {@link HelixParameterSpec} with a nonce and MAC.
     * 
     * @throws IOException
     *             if the test fails
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineGetParameterSpecForNonceAndMac() throws IOException, InvalidParameterSpecException {
        parameters.engineInit(asn1NonceAndMac);
        HelixParameterSpec paramSpec = parameters.engineGetParameterSpec(HelixParameterSpec.class);

        assertArrayEquals(TEST_VECTOR_3[NONCE], paramSpec.getNonce());
        assertArrayEquals(TEST_VECTOR_3[MAC], paramSpec.getMac());
    }

    /* tests for HelixAlgorithmParameters#engineGetEncoded() */

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineGetEncoded()} returns
     * the expected ASN.1 representation of a Helix nonce.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineGetEncodedForNonceOnly() throws InvalidParameterSpecException, IOException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        parameters.engineInit(paramSpec);

        assertArrayEquals(asn1Nonce, parameters.engineGetEncoded());
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineGetEncoded()} returns
     * the expected ASN.1 representation of a Helix nonce and MAC sequence.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineGetEncodedForNonceAndMac() throws InvalidParameterSpecException, IOException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        parameters.engineInit(paramSpec);

        assertArrayEquals(asn1NonceAndMac, parameters.engineGetEncoded());
    }

    /* test for HelixAlgorithmParameters#engineGetEncoded(String) */

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineGetEncoded()} throws
     * an exception if the specified format is not recognized.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test(expected = IOException.class)
    public void engineGetEncodedWithUnrecognizedFormat() throws InvalidParameterSpecException, IOException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE]);
        parameters.engineInit(paramSpec);

        parameters.engineGetEncoded("FAIL");
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineGetEncoded()} returns
     * the expected ASN.1 byte array when the format is <tt>null</tt>.
     * 
     * <p>
     * A <tt>null</tt> format indicates that the primary decoding format (ASN.1)
     * should be assumed.
     * </p>
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineGetEncodedWithNullFormat() throws InvalidParameterSpecException, IOException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        parameters.engineInit(paramSpec);

        assertArrayEquals(asn1NonceAndMac, parameters.engineGetEncoded(null));
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineGetEncoded()} returns
     * the expected ASN.1 byte array when the format is "ASN.1".
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void engineGetEncodedWithASN1Format() throws InvalidParameterSpecException, IOException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        parameters.engineInit(paramSpec);

        assertArrayEquals(asn1NonceAndMac, parameters.engineGetEncoded("ASN.1"));
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineGetEncoded()} returns
     * the expected ASN.1 byte array when the format is "DER".
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     * @throws IOException
     *             if the test fails
     */
    @Test
    public void testEngineGetEncoded_StringDer() throws InvalidParameterSpecException, IOException {
        AlgorithmParameterSpec paramSpec = new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]);
        parameters.engineInit(paramSpec);

        assertArrayEquals(asn1NonceAndMac, parameters.engineGetEncoded("DER"));
    }

    /* tests for HelixAlgorithmParameters#engineToString() */

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineToString()} returns
     * the generic string representation when both the nonce and MAC are
     * <tt>null</tt>.
     */
    @Test
    public void engineToStringWithNullNonceAndMac() {
        assertTrue(parameters.engineToString().startsWith(
                "net.ninthtest.crypto.provider.helix.HelixAlgorithmParameters@"));
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineToString()} returns
     * the expected string when initialized with a nonce only.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineToStringWithNonceOnly() throws InvalidParameterSpecException {
        parameters.engineInit(new HelixParameterSpec(TEST_VECTOR_3[NONCE]));

        assertEquals(TOSTRING_TEST_VECTOR_3_NONCE_ONLY, parameters.engineToString());
    }

    /**
     * Asserts that {@link HelixAlgorithmParameters#engineToString()} returns
     * the expected string when initialized with a nonce and MAC.
     * 
     * @throws InvalidParameterSpecException
     *             if the test fails
     */
    @Test
    public void engineToStringWithNonceAndMac() throws InvalidParameterSpecException {
        parameters.engineInit(new HelixParameterSpec(TEST_VECTOR_3[NONCE], TEST_VECTOR_3[MAC]));

        assertEquals(TOSTRING_TEST_VECTOR_3_NONCE_AND_MAC, parameters.engineToString());
    }
}
