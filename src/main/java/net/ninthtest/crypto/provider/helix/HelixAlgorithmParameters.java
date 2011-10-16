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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import net.ninthtest.security.Messages;
import net.ninthtest.security.provider.NinthTestProvider;

/**
 * Manages the algorithm parameters for Helix cryptographic operations.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public final class HelixAlgorithmParameters extends AlgorithmParametersSpi {
    /* the ASN.1 encoding format */
    private static final String ASN_1_ENCODING = "ASN.1";

    /* the DER encoding format */
    private static final String DER_ENCODING = "DER";

    /* the ASN.1 Sequence type */
    private static final byte ASN_1_SEQUENCE = 0x30;

    /* the ASN.1 OctetString type */
    private static final byte ASN_1_OCTET_STRING = 0x04;

    /* the Helix nonce bytes */
    private byte[] nonce;

    /* the Helix MAC bytes */
    private byte[] mac;

    /**
     * Creates a new <tt>HelixAlgorithmParameters</tt> and performs the provider
     * self-integrity check.
     */
    public HelixAlgorithmParameters() {
        NinthTestProvider.doSelfIntegrityCheck();
    }

    /**
     * Initializes this parameters object using the parameters specified in
     * <tt>paramSpec</tt>.
     * 
     * @param paramSpec the algorithm parameter specification (must be a
     *            {@link HelixParameterSpec})
     * @throws InvalidParameterSpecException if <i>paramSpec</i> is
     *             <tt>null</tt> or not a {@link HelixParameterSpec}
     * @see java.security.AlgorithmParametersSpi#engineInit(java.security.spec.AlgorithmParameterSpec)
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if ((paramSpec == null) || !(paramSpec instanceof HelixParameterSpec)) {
            throw new InvalidParameterSpecException(Messages.getMessage("helix.error.expect_helix_paramspec"));
        }

        HelixParameterSpec helixParamSpec = (HelixParameterSpec) paramSpec;

        nonce = helixParamSpec.getNonce();
        mac = helixParamSpec.getMac();
    }

    /**
     * Imports the specified parameters and decodes them according to the
     * primary decoding format for parameters.
     * 
     * <p>
     * Helix parameters are only encoded in ASN.1/DER format. There are two
     * valid ASN.1/DER encodings for Helix parameters, as specified below.
     * </p>
     * 
     * <p>
     * Nonce-only (18 bytes, expressed in hexadecimal below):
     * 
     * <pre>
     * 04 10 xx xx xx xx xx xx
     * xx xx xx xx xx xx xx xx
     * xx xx
     * </pre>
     * 
     * </p>
     * 
     * <p>
     * Nonce + MAC (38 bytes, expressed in hexadecimal below):
     * 
     * <pre>
     * 30 24 04 10 xx xx xx xx
     * xx xx xx xx xx xx xx xx
     * xx xx xx xx 04 10 xx xx
     * xx xx xx xx xx xx xx xx
     * xx xx xx xx xx xx
     * </pre>
     * 
     * </p>
     * 
     * @param params the ASN.1/DER-encoded parameters
     * @throws IOException if <i>params</i> cannot be decoded according to the
     *             specifications above
     * @see java.security.AlgorithmParametersSpi#engineInit(byte[])
     */
    @Override
    protected void engineInit(byte[] params) throws IOException {
        if ((params == null) || ((params.length != 18) && (params.length != 38))) {
            throw new IOException(Messages.getMessage("helix.error.invalid_asn1_params"));
        }

        if (params[0] == ASN_1_OCTET_STRING) {
            if (params[1] != 0x10) {
                throw new IOException(Messages.getMessage("helix.error.invalid_asn1_octet_string", 0,
                        (params[0] & 0xff), (params[1] & 0xff)));
            }

            nonce = new byte[16];
            System.arraycopy(params, 2, nonce, 0, 16);
        } else if (params[0] == ASN_1_SEQUENCE) {
            if (params[1] != 0x24) {
                throw new IOException(Messages.getMessage("helix.error.invalid_asn1_sequence", (params[1] & 0xff)));
            } else if ((params[2] != ASN_1_OCTET_STRING) || (params[3] != 0x10)) {
                throw new IOException(Messages.getMessage("helix.error.invalid_asn1_octet_string", 2,
                        (params[2] & 0xff), (params[3] & 0xff)));
            } else if ((params[20] != ASN_1_OCTET_STRING) || (params[21] != 0x10)) {
                throw new IOException(Messages.getMessage("helix.error.invalid_asn1_octet_string", 20,
                        (params[20] & 0xff), (params[21] & 0xff)));
            }

            nonce = new byte[16];
            System.arraycopy(params, 4, nonce, 0, 16);

            mac = new byte[16];
            System.arraycopy(params, 22, mac, 0, 16);
        } else {
            throw new IOException(Messages.getMessage("helix.error.invalid_asn1_tag", (params[0] & 0xff)));
        }
    }

    /**
     * Imports the parameters from <tt>params</tt> and decodes them according to
     * the specified decoding format.
     * 
     * <p>
     * Helix algorithm parameters only recognize ASN.1 or DER encoding.
     * </p>
     * 
     * <p>
     * If <i>format</i> is non-<tt>null</tt> and <b>not</b> ASN.1 or DER, an
     * attempt is made to decode <i>params</i> as ASN.1; if this attempt fails,
     * an {@link IOException} is thrown.
     * </p>
     * 
     * <p>
     * If <i>format</i> is <tt>null</tt>, <i>params</i> is decoded assuming
     * ASN.1.
     * </p>
     * 
     * @param params the encoded parameters
     * @param format the name of the decoding format (should be
     *            &quot;ASN.1&quot; or &quot;DER&quot;)
     * @throws IOException if <i>params</i> cannot be decoded
     * @see java.security.AlgorithmParametersSpi#engineInit(byte[],
     *      java.lang.String)
     */
    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        if ((format == null) || ASN_1_ENCODING.equals(format) || DER_ENCODING.equals(format)) {
            engineInit(params);
        } else {
            // try ASN.1 anyway
            try {
                engineInit(params);
            } catch (IOException ex) {
                throw new IOException(Messages.getMessage("helix.error.invalid_params_encoding", format), ex);
            }
        }
    }

    /**
     * Returns a (transparent) specification of this parameters object.
     * 
     * @param paramSpec the specification class in which the parameters should
     *            be returned (must be {@link HelixParameterSpec})
     * @return the Helix parameter specification
     * @throws InvalidParameterSpecException if <i>paramSpec</i> is
     *             <tt>null</tt> or not equal to the class of
     *             {@link HelixParameterSpec}
     * @see java.security.AlgorithmParametersSpi#engineGetParameterSpec(java.lang.Class)
     */
    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if ((paramSpec == null) || !paramSpec.equals(HelixParameterSpec.class)) {
            throw new InvalidParameterSpecException(Messages.getMessage("helix.error.invalid_paramspec"));
        }

        if (mac == null) {
            return (T) new HelixParameterSpec(nonce);
        } else {
            return (T) new HelixParameterSpec(nonce, mac);
        }
    }

    /**
     * Returns the parameters in their primary encoding format.
     * 
     * <p>
     * Helix parameters are only encoded in ASN.1/DER format. There are two
     * valid ASN.1/DER encodings for Helix parameters, as specified below.
     * </p>
     * 
     * <p>
     * Nonce-only (18 bytes, expressed in hexadecimal below):
     * 
     * <pre>
     * 04 10 xx xx xx xx xx xx
     * xx xx xx xx xx xx xx xx
     * xx xx
     * </pre>
     * 
     * </p>
     * 
     * <p>
     * Nonce + MAC (38 bytes, expressed in hexadecimal below):
     * 
     * <pre>
     * 30 24 04 10 xx xx xx xx
     * xx xx xx xx xx xx xx xx
     * xx xx xx xx 04 10 xx xx
     * xx xx xx xx xx xx xx xx
     * xx xx xx xx xx xx
     * </pre>
     * 
     * </p>
     * 
     * @return the ASN.1/DER-encoded Helix parameters
     * @throws IOException if an error occurs while encoding the Helix
     *             parameters
     * @see java.security.AlgorithmParametersSpi#engineGetEncoded()
     */
    @Override
    protected byte[] engineGetEncoded() throws IOException {
        byte[] asn1 = null;

        if (mac == null) {
            asn1 = new byte[18];
            asn1[0] = ASN_1_OCTET_STRING;
            asn1[1] = 0x10;

            System.arraycopy(nonce, 0, asn1, 2, 16);
        } else {
            asn1 = new byte[38];
            asn1[0] = ASN_1_SEQUENCE;
            asn1[1] = 0x24;

            asn1[2] = ASN_1_OCTET_STRING;
            asn1[3] = 0x10;
            System.arraycopy(nonce, 0, asn1, 4, 16);

            asn1[20] = ASN_1_OCTET_STRING;
            asn1[21] = 0x10;
            System.arraycopy(mac, 0, asn1, 22, 16);
        }

        return asn1;
    }

    /**
     * Returns the parameters encoded in the specified format.
     * 
     * <p>
     * Helix parameters are only encoded in ASN.1/DER format.
     * </p>
     * 
     * <p>
     * If <i>format</i> is non-<tt>null</tt> and <b>not</b> ASN.1 or DER, an
     * {@link IOException} is thrown.
     * </p>
     * 
     * <p>
     * If <i>format</i> is <tt>null</tt>, <i>params</i> is encoded assuming
     * ASN.1.
     * </p>
     * 
     * @param format the name of the encoding format (should be
     *            &quot;ASN.1&quot;, &quot;DER&quot;, or <tt>null</tt>)
     * @return the ASN.1/DER-encoded Helix parameters
     * @throws IOException if <i>format</i> is non-<tt>null</tt> and not
     *             &quot;ASN.1&quot; or &quot;DER&quot;; or if an error occurs
     *             while encoding the Helix parameters
     * @see java.security.AlgorithmParametersSpi#engineGetEncoded(java.lang.String)
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if ((format != null) && !(ASN_1_ENCODING.equals(format) || DER_ENCODING.equals(format))) {
            throw new IOException(Messages.getMessage("helix.error.invalid_params_encoding", format));
        }

        return engineGetEncoded();
    }

    /**
     * Returns a formatted string describing the parameters.
     * 
     * <p>
     * This method returns the appropriate PDU (protocol data unit) for the
     * Helix parameters represented by this instance, according to the following
     * ASN.1/DER type specification:
     * 
     * <pre>
     * HelixParameters DEFINITIONS ::= BEGIN
     * 
     *     HelixNonce ::= OCTETSTRING
     * 
     *     HelixNonceAndMac ::= SEQUENCE {
     *         nonce   OCTETSTRING,
     *         mac     OCTETSTRING
     *     }
     * 
     * END
     * </pre>
     * 
     * </p>
     * 
     * <p>
     * If this instance represents a Helix nonce only, the following PDU is
     * returned:
     * 
     * <pre>
     * helixParameters HelixNonce ::= {"xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx"}
     * </pre>
     * 
     * </p>
     * 
     * <p>
     * If this instance represents a Helix nonce <b>and</b> MAC, the following
     * PDU is returned:
     * 
     * <pre>
     * helixParameters HelixNonceAndMac ::= {
     *     nonce   "xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx",
     *     mac     "xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx"
     * }
     * </pre>
     * 
     * </p>
     * 
     * <p>
     * All bytes represented in PDUs are in hexadecimal format. If this instance
     * has not yet been initialized, this method will return the result of
     * <tt>super.toString()</tt>.
     * </p>
     * 
     * @return the appropriate PDU representation of this instance (as described
     *         above), or the result of <tt>super.toString()</tt> if this
     *         instance has not been initialized
     * @see java.security.AlgorithmParametersSpi#engineToString()
     */
    @Override
    protected String engineToString() {
        if ((nonce == null) && (mac == null)) {
            return super.toString();
        }

        if (mac == null) {
            return new StringBuilder(82).append("helixParameters HelixNonce ::= {\"").append(bytesToHexString(nonce)).append(
                    "\"}").toString();
        } else {
            return new StringBuilder(117).append("helixParameters HelixNonceAndMac ::= {\n    nonce  \"").append(
                    bytesToHexString(nonce)).append("\",\n    mac    \"").append(bytesToHexString(mac)).append("\"\n}").toString();
        }
    }

    /* Converts an array of bytes to a hexadecimal string. */
    private String bytesToHexString(final byte[] bytes) {
        StringBuilder hex = new StringBuilder(47);

        for (int i = 0; i < bytes.length; ++i) {
            if (i > 0) {
                hex.append(' ');
            }

            String h = Integer.toHexString(bytes[i] & 0xff);
            if (h.length() == 1) {
                h = "0" + h;
            }

            hex.append(h);
        }

        return hex.toString();
    }
}
