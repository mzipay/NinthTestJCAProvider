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

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import net.ninthtest.crypto.MessageAuthenticationException;
import net.ninthtest.crypto.helix.HelixDecryption;
import net.ninthtest.crypto.helix.HelixEncryption;
import net.ninthtest.crypto.helix.HelixPrimitive;
import net.ninthtest.security.Messages;
import net.ninthtest.security.provider.NinthTestProvider;

/**
 * This class provides encryption and decryption (with optional MAC generation
 * and verification) operations for the Helix stream cipher.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 * @see <a href="http://www.schneier.com/paper-helix.html">Helix: Fast
 *      Encryption and Authentication in a Single Cryptographic Primitive</a>
 */
public final class HelixCipher extends CipherSpi {
    /*
     * the names corresponding to the wrappedKeyType argument to #engineUnwrap()
     * (used to create meaningful error messages)
     */
    private static final String[] KEY_TYPE_NAMES = new String[] {null, "PUBLIC_KEY", "PRIVATE_KEY", "SECRET_KEY"};

    /*
     * operation mode of this cipher (ENCRYPT_MODE, DECRYPT_MODE, WRAP_MODE, or
     * UNWRAP_MODE)
     */
    private int opmode = -1;

    /* the Helix algorithm parameters */
    private AlgorithmParameters parameters;

    /*
     * the cryptographic primitive used by this cipher (one-time use; a new
     * instance is created each time the cipher is initialized)
     */
    private HelixPrimitive primitive;

    /**
     * Creates a new <tt>HelixCipher</tt> and performs the provider
     * self-integrity check.
     */
    public HelixCipher() {
        NinthTestProvider.doSelfIntegrityCheck();
    }

    /**
     * Returns the block size (in bytes).
     * 
     * @return 0 (zero; Helix is a stream cipher)
     * @see javax.crypto.CipherSpi#engineGetBlockSize()
     */
    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    /**
     * Returns the key size of the given <tt>key</tt> object in bits.
     * 
     * @param key
     *            a Helix {@link SecretKey}
     * @return the size of <i>key</i> expressed in number of bits
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt> or not a Helix
     *             {@link SecretKey}
     * @see javax.crypto.CipherSpi#engineGetKeySize(java.security.Key)
     */
    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if ((key == null) || !(key instanceof SecretKey) || !NinthTestProvider.HELIX.equals(key.getAlgorithm())) {
            throw new InvalidKeyException(Messages.getMessage("helix.error.expect_secret_key"));
        }

        return (key.getEncoded().length * 8);
    }

    /**
     * Initializes this cipher with a key and a source of randomness.
     * 
     * <p>
     * Initializing the cipher in this manner causes the Helix <i>nonce</i> to
     * be randomly generated; therefore, this method can only be used to
     * initialize the cipher for <b>encryption</b> or <b>key wrapping</b>.
     * </p>
     * 
     * <p>
     * The randomly-generated <i>nonce</i> can be retrieved directly via
     * {@link Cipher#getIV()} or indirectly via {@link Cipher#getParameters()}.
     * </p>
     * 
     * @param opmode
     *            the operation mode of this cipher (restricted to
     *            {@link Cipher#ENCRYPT_MODE} or {@link Cipher#WRAP_MODE})
     * @param key
     *            the secret key to be used for encryption or key wrapping (must
     *            be a Helix {@link SecretKey})
     * @param random
     *            the RNG
     * @throws IllegalArgumentException
     *             if the operation mode is {@link Cipher#DECRYPT_MODE} or
     *             {@link Cipher#UNWRAP_MODE}
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt> or is not a Helix
     *             {@link SecretKey}
     * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key,
     *      java.security.SecureRandom)
     */
    @Override
    protected void engineInit(@SuppressWarnings("hiding") int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        resetInternalState();

        if ((Cipher.DECRYPT_MODE == opmode) || (Cipher.UNWRAP_MODE == opmode)) {
            throw new IllegalArgumentException(Messages.getMessage("helix.error.nonce_is_missing"));
        } else if ((key == null) || !(key instanceof SecretKey) || !NinthTestProvider.HELIX.equals(key.getAlgorithm())) {
            throw new InvalidKeyException(Messages.getMessage("helix.error.expect_secret_key"));
        }

        this.opmode = opmode;

        byte[] randomNonce = new byte[16];
        if (random != null) {
            random.nextBytes(randomNonce);
        } else {
            (new SecureRandom()).nextBytes(randomNonce);
        }

        try {
            parameters = createHelixAlgorithmParameters(new HelixParameterSpec(randomNonce));
        } catch (InvalidParameterSpecException ex) {
            throw new ProviderException(Messages.getMessage("helix.error.failed_to_create_params"), ex);
        }

        primitive = new HelixEncryption(key.getEncoded(), randomNonce);
    }

    /**
     * Initializes this cipher with a key, a set of algorithm parameters, and a
     * source of randomness.
     * 
     * <p>
     * When <i>opmode</i> is {@link Cipher#DECRYPT_MODE} or
     * {@link Cipher#UNWRAP_MODE}, a MAC specified in <i>params</i> <b>must</b>
     * be exactly 16 bytes in length, in which case {@link Cipher#doFinal()}
     * will fail unless the generated MAC matches the MAC specified in
     * <i>params</i>. Otherwise, the MAC can be left <tt>null</tt>, causing MAC
     * verification to be skipped.
     * </p>
     * 
     * <p>
     * When <i>opmode</i> is {@link Cipher#ENCRYPT_MODE} or
     * {@link Cipher#WRAP_MODE}, a MAC <b>must not</b> be specified in
     * <i>params</i>. After {@link Cipher#doFinal()} completes successfully, the
     * <i>generated</i> MAC can be retrieved indirectly via
     * {@link Cipher#getParameters()} (<b>prior</b> to this cipher being
     * re-initialized).
     * </p>
     * 
     * @param opmode
     *            the operation mode of this cipher
     * @param key
     *            a Helix {@link SecretKey}
     * @param params
     *            a {@link HelixParameterSpec}
     * @param random
     *            the RNG (not used)
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt> or is not a Helix
     *             {@link SecretKey}; or if the algorithm parameters cannot be
     *             initialized from the parameter spec
     * @throws InvalidAlgorithmParameterException
     *             if <i>params</i> is <tt>null</tt> or is not a
     *             {@link HelixParameterSpec}; or if a non-<tt>null</tt> MAC in
     *             <i>params</i> is not exactly 16 bytes in length; or if a non-
     *             <tt>null</tt> MAC is specified in <i>params</i> when
     *             <i>opmode</i> is {@link Cipher#ENCRYPT_MODE} or
     *             {@link Cipher#WRAP_MODE}
     * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key,
     *      java.security.spec.AlgorithmParameterSpec,
     *      java.security.SecureRandom)
     */
    @Override
    protected void engineInit(@SuppressWarnings("hiding") int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        resetInternalState();

        if ((key == null) || !(key instanceof SecretKey) || !NinthTestProvider.HELIX.equals(key.getAlgorithm())) {
            throw new InvalidKeyException(Messages.getMessage("helix.error.expect_secret_key"));
        } else if ((params == null) || !(params instanceof HelixParameterSpec)) {
            throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.expect_helix_paramspec"));
        }

        HelixParameterSpec parameterSpec = (HelixParameterSpec) params;
        checkParameterSpec(opmode, parameterSpec);

        this.opmode = opmode;

        try {
            parameters = createHelixAlgorithmParameters(parameterSpec);
        } catch (InvalidParameterSpecException ex) {
            throw new ProviderException(Messages.getMessage("helix.error.failed_to_create_params"), ex);
        }

        if ((Cipher.ENCRYPT_MODE == opmode) || (Cipher.WRAP_MODE == opmode)) {
            primitive = new HelixEncryption(key.getEncoded(), parameterSpec.getNonce());
        } else {
            primitive = new HelixDecryption(key.getEncoded(), parameterSpec.getNonce(), parameterSpec.getMac());
        }
    }

    /**
     * Initializes this cipher with a key, a set of algorithm parameters, and a
     * source of randomness.
     * 
     * <p>
     * When <i>opmode</i> is {@link Cipher#DECRYPT_MODE} or
     * {@link Cipher#UNWRAP_MODE}, a MAC specified in <i>params</i> <b>must</b>
     * be exactly 16 bytes in length, in which case {@link Cipher#doFinal()}
     * will fail unless the generated MAC matches the MAC specified in
     * <i>params</i>. Otherwise, the MAC can be left <tt>null</tt>, causing MAC
     * verification to be skipped.
     * </p>
     * 
     * <p>
     * When <i>opmode</i> is {@link Cipher#ENCRYPT_MODE} or
     * {@link Cipher#WRAP_MODE}, a MAC <b>must not</b> be specified in
     * <i>params</i>. After {@link Cipher#doFinal()} completes successfully, the
     * <i>generated</i> MAC can be retrieved indirectly via
     * {@link Cipher#getParameters()} (<b>prior</b> to this cipher being
     * re-initialized).
     * </p>
     * 
     * @param opmode
     *            the operation mode of this cipher
     * @param key
     *            a Helix {@link SecretKey}
     * @param params
     *            Helix algorithm parameters provided by NinthTest
     * @param random
     *            the RNG (not used)
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt> or is not a Helix
     *             {@link SecretKey}
     * @throws InvalidAlgorithmParameterException
     *             if <i>params</i> is <tt>null</tt> or is not a Helix
     *             {@link AlgorithmParameters} provided by NinthTest; or if a
     *             {@link HelixParameterSpec} cannot be derived from
     *             <i>params</i>; or if a non-<tt>null</tt> MAC in <i>params</i>
     *             is not exactly 16 bytes in length; or if a non-<tt>null</tt>
     *             MAC is specified in <i>params</i> when <i>opmode</i> is
     *             either {@link Cipher#ENCRYPT_MODE} or
     *             {@link Cipher#WRAP_MODE}
     * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key,
     *      java.security.AlgorithmParameters, java.security.SecureRandom)
     */
    @Override
    protected void engineInit(@SuppressWarnings("hiding") int opmode, Key key, AlgorithmParameters params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        resetInternalState();

        if ((key == null) || !(key instanceof SecretKey) || !NinthTestProvider.HELIX.equals(key.getAlgorithm())) {
            throw new InvalidKeyException(Messages.getMessage("helix.error.expect_secret_key"));
        } else if ((params == null) || !NinthTestProvider.HELIX.equals(params.getAlgorithm())
                || !NinthTestProvider.NAME.equals(params.getProvider().getName())) {
            throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.expect_helix_params"));
        }

        HelixParameterSpec parameterSpec = null;
        try {
            parameterSpec = params.getParameterSpec(HelixParameterSpec.class);
        } catch (InvalidParameterSpecException ex) {
            throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.failed_to_get_paramspec"), ex);
        }

        checkParameterSpec(opmode, parameterSpec);

        this.opmode = opmode;

        parameters = params;

        if ((Cipher.ENCRYPT_MODE == opmode) || (Cipher.WRAP_MODE == opmode)) {
            primitive = new HelixEncryption(key.getEncoded(), parameterSpec.getNonce());
        } else {
            primitive = new HelixDecryption(key.getEncoded(), parameterSpec.getNonce(), parameterSpec.getMac());
        }
    }

    /*
     * Resets the internal state of this cipher so that it can be re-used.
     * 
     * This method is always called as the first step of the overloaded
     * #engineInit methods.
     */
    private void resetInternalState() {
        opmode = -1;
        parameters = null;
        primitive = null;
    }

    /*
     * Ensures that a parameter specification is valid with respect to the
     * operation mode.
     * 
     * If the operation mode is ENCRYPT_MODE or WRAP_MODE, the parameter
     * specification must not have a non-null MAC.
     * 
     * If the operation mode is DECRYPT_MODE or UNWRAP_MODE, the parameter
     * specification may have a null MAC (in which case MAC verification is
     * skipped); if the MAC is non-null, it must be exactly 16 bytes in length.
     */
    private void checkParameterSpec(@SuppressWarnings("hiding") int opmode, HelixParameterSpec spec)
            throws InvalidAlgorithmParameterException {
        byte[] mac = spec.getMac();
        if (mac != null) {
            if ((Cipher.ENCRYPT_MODE == opmode) || (Cipher.WRAP_MODE == opmode)) {
                throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.mac_not_expected"));
            } else if (mac.length != 16) { // DECRYPT_MODE || UNWRAP_MODE
                throw new InvalidAlgorithmParameterException(Messages.getMessage("helix.error.invalid_mac_length"));
            }
        }
    }

    /* Creates an instance of HelixAlgorithmParameters using parameterSpec. */
    private AlgorithmParameters createHelixAlgorithmParameters(HelixParameterSpec parameterSpec)
            throws InvalidParameterSpecException {
        AlgorithmParameters algorithmParameters =
                new AlgorithmParameters(new HelixAlgorithmParameters(), new NinthTestProvider(),
                        NinthTestProvider.HELIX) {
                    // nothing overridden
                };
        algorithmParameters.init(parameterSpec);

        return algorithmParameters;
    }

    /**
     * Sets the mode of this cipher.
     * 
     * <p>
     * This method always throws {@link UnsupportedOperationException}.
     * </p>
     * 
     * @param mode
     *            the cipher mode
     * @throws NoSuchAlgorithmException
     *             if the requested cipher mode does not exist
     * @throws UnsupportedOperationException
     *             if this method is invoked
     * @see javax.crypto.CipherSpi#engineSetMode(java.lang.String)
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        /*
         * should never happen; if a mode is specified in the cipher
         * transformation string (e.g. "Helix/MODE"), javax.crypto.Cipher should
         * throw java.security.NoSuchAlgorithmException before this method would
         * be invoked
         */
        throw new UnsupportedOperationException(Messages.getMessage("helix.error.unsupported_mode", mode));
    }

    /**
     * Sets the padding mechanism of this cipher.
     * 
     * <p>
     * This method always throws {@link UnsupportedOperationException}.
     * </p>
     * 
     * @param padding
     *            the cipher padding method
     * @throws NoSuchPaddingException
     *             if the requested padding mechanism does not exist
     * @throws UnsupportedOperationException
     *             if this method is invoked
     * @see javax.crypto.CipherSpi#engineSetPadding(java.lang.String)
     */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        /*
         * should never happen; if a padding method is specified in the cipher
         * transformation string (e.g. "Helix/???/PaddingMethod"),
         * javax.crypto.Cipher should throw
         * java.security.NoSuchAlgorithmException before this method would be
         * invoked
         */
        throw new UnsupportedOperationException(Messages.getMessage("helix.error.unsupported_padding", padding));
    }

    /**
     * Returns the parameters used with this cipher.
     * 
     * <p>
     * This method provides one way of obtaining the randomly-generated nonce
     * after initialization (the other being the {@link Cipher#getIV()} method).
     * </p>
     * 
     * <p>
     * The nonce is randomly generated if the cipher is initialized using
     * {@link Cipher#init(int, Key)} or
     * {@link Cipher#init(int, Key, SecureRandom)}.
     * </p>
     * 
     * <p>
     * This method also allows for the retrieval of the generated MAC following
     * a successful encryption or key-wrapping operation.
     * </p>
     * 
     * @return the algorithm parameters used for the current operation, or
     *         <tt>null</tt> if this cipher has not yet been initialized
     * @see javax.crypto.CipherSpi#engineGetParameters()
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return parameters;
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     * 
     * <p>
     * This method provides one way of obtaining the randomly-generated nonce
     * after initialization (the other being the {@link Cipher#getParameters()}
     * method).
     * </p>
     * 
     * <p>
     * The nonce is randomly generated if the cipher is initialized using
     * {@link Cipher#init(int, Key)} or
     * {@link Cipher#init(int, Key, SecureRandom)}.
     * </p>
     * 
     * @return the Helix nonce used for the current operation, or <tt>null</tt>
     *         if this cipher has not yet been initialized
     * @see javax.crypto.CipherSpi#engineGetIV()
     */
    @Override
    protected byte[] engineGetIV() {
        if (parameters == null) {
            return null;
        }

        HelixParameterSpec parameterSpec = null;
        try {
            parameterSpec = parameters.getParameterSpec(HelixParameterSpec.class);
        } catch (InvalidParameterSpecException ex) {
            /*
             * should never happen; if `parameters' is non-null, it must have
             * passed validation (meaning it must reference a valid
             * HelixAlgorithmParameters)
             */
            return null;
        }

        return parameterSpec.getNonce();
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next <tt>update</tt> or <tt>doFinal</tt>
     * operation, given the input length <tt>inputLen</tt> (in bytes).
     * 
     * <p>
     * Up to three input bytes <i>may</i> be buffered when {@link Cipher#update}
     * is called, because input is processed by the underlying Helix primitive
     * one word (i.e. one 32-bit integer) at a time.
     * </p>
     * 
     * @param inputLen
     *            the number of input bytes that will be passed to the
     *            <i>next</i> {@link Cipher#update} or {@link Cipher#doFinal()}
     *            operation
     * @return the size that the output buffer would need to be to hold the
     *         result of the <i>next</i> {@link Cipher#update} or
     *         {@link Cipher#doFinal} operation (given input of length
     *         <i>inputLen</i>)
     * @see javax.crypto.CipherSpi#engineGetOutputSize(int)
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (inputLen < 0) {
            throw new IllegalArgumentException(Messages.getMessage("error.negative_input_length"));
        }

        /*
         * if the cipher is not yet initialized, the primitive will be null, in
         * which case using zero as the buffer size will still yield the correct
         * result since the next call to #update() or #doFinal() can't occur
         * unless/until the cipher is initialized (and the buffer size at that
         * time will be zero)
         * 
         * if the cipher has already been initialized, but an operation has been
         * completed, the call to HelixPrimitive#bufferSize() will throw
         * IllegalStateException
         */
        int buffered = (primitive != null) ? primitive.bufferSize() : 0;

        return (buffered + inputLen);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     * 
     * <p>
     * If the <i>input</i> (combined with any previously-buffered input) is not
     * long enough to yield at least four bytes of output, <i>input</i> will be
     * buffered and this method will return <tt>null</tt>.
     * </p>
     * 
     * <p>
     * If this method returns non-<tt>null</tt>, the returned byte array will
     * always have a length that is a multiple of four.
     * </p>
     * 
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the index into <i>input</i> where the input bytes begin
     * @param inputLen
     *            the number of bytes to be used from <i>input</i> (beginning at
     *            <i>inputOffset</i>)
     * @return four or more bytes of output, or <tt>null</tt> if there are not
     *         enough input bytes to yield at least four bytes of output
     * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int)
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if ((input == null)) {
            throw new IllegalArgumentException(Messages.getMessage("error.input_buffer_is_required"));
        } else if ((inputOffset < 0) || (inputOffset >= input.length)) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_input_offset"));
        } else if ((inputLen < 0) || (inputLen > (input.length - inputOffset))) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_input_length"));
        }

        byte[] part = new byte[inputLen];
        System.arraycopy(input, inputOffset, part, 0, inputLen);

        return primitive.feed(part);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     * 
     * <p>
     * If the <i>input</i> (combined with any previously-buffered input) is not
     * long enough to yield at least four bytes of output, <i>input</i> will be
     * buffered, <i>output</i> will <b>not</b> be modified, and this method will
     * return 0 (zero).
     * </p>
     * 
     * <p>
     * The integer returned by this method will always be a multiple of four (or
     * zero, as described above).
     * </p>
     * 
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the index into <i>input</i> where the input bytes begin
     * @param inputLen
     *            the number of bytes to be used from <i>input</i> (beginning at
     *            <i>inputOffset</i>)
     * @param output
     *            the buffer for the result
     * @param outputOffset
     *            the index into <i>output</i> where the output bytes are stored
     * @return the number of bytes that were written to <i>output</i>, or 0
     *         (zero) if there was not enough input to produce at least four
     *         bytes of output
     * @throws ShortBufferException
     *             if <i>output</i> (beginning at <i>outputOffset</i>) is not
     *             large enough to store the number of bytes produced by this
     *             call
     * @see javax.crypto.CipherSpi#engineUpdate(byte[], int, int, byte[], int)
     */
    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        if (output == null) {
            throw new IllegalArgumentException(Messages.getMessage("error.output_buffer_is_required"));
        } else if ((outputOffset < 0) || (outputOffset >= output.length)) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_output_offset"));
        }

        byte[] processed = engineUpdate(input, inputOffset, inputLen);
        if (processed == null) {
            return 0;
        }
        int processedLength = processed.length;

        if (processedLength <= (output.length - outputOffset)) {
            System.arraycopy(processed, 0, output, outputOffset, processedLength);
        } else {
            throw new ShortBufferException(Messages.getMessage("error.output_buffer_too_small"));
        }

        return processedLength;
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * <p>
     * If the current operation mode is {@link Cipher#ENCRYPT_MODE}, the
     * Helix-generated MAC will be stored in the algorithm parameters. The MAC
     * can be retrieved indirectly via {@link Cipher#getParameters()}
     * <b>prior</b> to this cipher being re-initialized.
     * </p>
     * 
     * <p>
     * If the current operation mode is {@link Cipher#DECRYPT_MODE}, and the
     * expected MAC was specified when this cipher was initialized, the expected
     * MAC will be compared to the MAC that was generated for this operation. If
     * the expected and generated MACs are not equal, this method will throw
     * {@link MessageAuthenticationException}.
     * </p>
     * 
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the index into <i>input</i> where the input bytes begin
     * @param inputLen
     *            the number of bytes to be used from <i>input</i> (beginning at
     *            <i>inputOffset</i>)
     * @return all remaining bytes of output
     * @throws IllegalBlockSizeException
     *             never (Helix is a stream cipher)
     * @throws BadPaddingException
     *             never (Helix padding is masked off)
     * @throws MessageAuthenticationException
     *             for a decryption operation only, if the non-<tt>null</tt>
     *             expected MAC does not match the generated MAC
     * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int)
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException,
            BadPaddingException {
        if ((input == null)) {
            throw new IllegalArgumentException(Messages.getMessage("error.input_buffer_is_required"));
        } else if ((inputOffset < 0) || (inputOffset >= input.length)) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_input_offset"));
        } else if ((inputLen < 0) || (inputLen > (input.length - inputOffset))) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_input_length"));
        }

        byte[] lastPart = new byte[inputLen];
        System.arraycopy(input, inputOffset, lastPart, 0, inputLen);

        /*
         * if the Cipher is in DECRYPT_MODE and an expected MAC was specified in
         * the parameters, this will throw MessageAuthenticationException if MAC
         * verification fails
         */
        byte[] processed = primitive.finish(lastPart);

        if (opmode == Cipher.ENCRYPT_MODE) {
            updateParametersWithMac(primitive.getGeneratedMac());
        }

        return processed;
    }

    /*
     * Stores the generated MAC in the algorithm paramters.
     * 
     * This is an arguably incorrect use of {@link AlgorithmParameters}, but it
     * is the only way to provide the generated MAC to the caller. This usage is
     * considered justified since the combined MAC function is a differentiating
     * feature of Helix.
     */
    private void updateParametersWithMac(final byte[] generatedMac) {
        try {
            HelixParameterSpec parameterSpec = parameters.getParameterSpec(HelixParameterSpec.class);
            byte[] nonce = parameterSpec.getNonce();
            parameterSpec = new HelixParameterSpec(nonce, generatedMac);
            parameters = createHelixAlgorithmParameters(parameterSpec);
        } catch (Exception ex) {
            /*
             * should never happen; by the time this method is called, the
             * AlgorithmParameters have already been verified, and at least one
             * successful call to AlgorithmParameters#getParameterSpec() has
             * already occurred
             */
            throw new ProviderException(ex);
        }
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     * 
     * <p>
     * If the current operation mode is {@link Cipher#ENCRYPT_MODE}, the
     * generated MAC will be stored in the algorithm parameters, and can be
     * retrieved indirectly via {@link Cipher#getParameters()} <b>prior</b> to
     * re-initializing this cipher.
     * </p>
     * 
     * <p>
     * If the current operation mode is {@link Cipher#DECRYPT_MODE}, and the
     * expected MAC was specified when this cipher was initialized, the expected
     * MAC will be compared to the MAC that was generated for this operation. If
     * the expected and generated MACs are not equal, this method will throw
     * {@link MessageAuthenticationException}.
     * </p>
     * 
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the index into <i>input</i> where the input bytes begin
     * @param inputLen
     *            the number of bytes to be used from <i>input</i> (beginning at
     *            <i>inputOffset</i>)
     * @param output
     *            the buffer for the result
     * @param outputOffset
     *            the index into <i>output</i> where the output bytes are stored
     * @return all remaining bytes of output
     * @throws ShortBufferException
     *             if <i>output</i> (beginning at <i>outputOffset</i>) is not
     *             large enough to store the number of bytes produced by this
     *             call
     * @throws IllegalBlockSizeException
     *             never (Helix is a stream cipher)
     * @throws BadPaddingException
     *             never (Helix padding is masked off)
     * @throws MessageAuthenticationException
     *             for a decryption operation only, if the non-<tt>null</tt>
     *             expected MAC does not match the generated MAC
     * @see javax.crypto.CipherSpi#engineDoFinal(byte[], int, int, byte[], int)
     */
    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if (output == null) {
            throw new IllegalArgumentException(Messages.getMessage("error.output_buffer_is_required"));
        } else if ((outputOffset < 0) || (outputOffset >= output.length)) {
            throw new IllegalArgumentException(Messages.getMessage("error.invalid_output_offset"));
        }

        byte[] processed = engineDoFinal(input, inputOffset, inputLen);
        int processedLength = processed.length;

        if (processedLength <= (output.length - outputOffset)) {
            System.arraycopy(processed, 0, output, outputOffset, processedLength);
        } else {
            throw new ShortBufferException(Messages.getMessage("error.output_buffer_too_small"));
        }

        return processedLength;
    }

    /**
     * Wraps a key.
     * 
     * @param key
     *            the key to be wrapped
     * @return the wrapped key
     * @throws IllegalBlockSizeException
     *             never (Helix is a stream cipher)
     * @throws InvalidKeyException
     *             if <i>key</i> is <tt>null</tt>
     * @see javax.crypto.CipherSpi#engineWrap(java.security.Key)
     */
    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException(Messages.getMessage("error.key_is_required"));
        }

        byte[] cipherText = primitive.finish(key.getEncoded());
        byte[] generatedMac = primitive.getGeneratedMac();

        updateParametersWithMac(generatedMac);

        return cipherText;
    }

    /**
     * Unwraps a previously wrapped key.
     * 
     * <p>
     * If the expected MAC was specified when this cipher was initialized, the
     * expected MAC will be compared to the MAC that was generated for this
     * operation. If the expected and generated MACs are not equal, this method
     * will throw {@link MessageAuthenticationException}.
     * </p>
     * 
     * @param wrappedKey
     *            the key to be unwrapped
     * @param wrappedKeyAlgorithm
     *            the algorithm associated with the wrapped key
     * @param wrappedKeyType
     *            the type of the wrapped key ( {@link Cipher#SECRET_KEY},
     *            {@link Cipher#PRIVATE_KEY}, or {@link Cipher#PUBLIC_KEY})
     * @return the unwrapped key
     * @throws InvalidKeyException
     *             if <i>wrappedKey</i> does not represent a key of type
     *             <i>wrappedKeyType</i> for the <i>wrappedKeyAlgorithm</i>
     * @throws NoSuchAlgorithmException
     *             if no installed providers can create keys of type
     *             <i>wrappedKeyType</i> for the <i>wrappedKeyAlgorithm</i>
     * @throws MessageAuthenticationException
     *             if the non-<tt>null</tt> expected MAC does not match the
     *             generated MAC
     * @see javax.crypto.CipherSpi#engineUnwrap(byte[], java.lang.String, int)
     */
    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKey == null) {
            throw new InvalidKeyException(Messages.getMessage("error.key_is_required"));
        } else if ((wrappedKeyAlgorithm == null) || wrappedKeyAlgorithm.isEmpty()) {
            throw new NoSuchAlgorithmException(Messages.getMessage("error.key_algorithm_name_is_required"));
        }

        /*
         * if an expected MAC was specified in the parameters when initializing
         * the cipher, this will throw MessageAuthenticationException if MAC
         * verification fails
         */
        byte[] plainText = primitive.finish(wrappedKey);

        Key unwrappedKey = null;
        try {
            switch (wrappedKeyType) {
            case Cipher.PUBLIC_KEY:
                X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(plainText);
                unwrappedKey = KeyFactory.getInstance(wrappedKeyAlgorithm).generatePublic(x509Spec);
                break;
            case Cipher.PRIVATE_KEY:
                PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(plainText);
                unwrappedKey = KeyFactory.getInstance(wrappedKeyAlgorithm).generatePrivate(pkcs8Spec);
                break;
            case Cipher.SECRET_KEY:
                SecretKeySpec secretSpec = new SecretKeySpec(plainText, wrappedKeyAlgorithm);
                try {
                    unwrappedKey = SecretKeyFactory.getInstance(wrappedKeyAlgorithm).generateSecret(secretSpec);
                } catch (GeneralSecurityException ex) {
                    unwrappedKey = secretSpec;
                }
                break;
            default:
                /*
                 * should never happen; Cipher#unwrap() verifies the key type
                 * before delegating to CipherSpi
                 */
                throw new IllegalArgumentException(Messages.getMessage("error.invalid_key_type"));
            }
        } catch (InvalidKeySpecException ex) {
            throw new InvalidKeyException(Messages.getMessage("error.failed_to_create_key", wrappedKeyAlgorithm,
                    KEY_TYPE_NAMES[wrappedKeyType]), ex);
        }

        return unwrappedKey;
    }
}
