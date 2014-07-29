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

package net.ninthtest.crypto;

import java.security.ProviderException;

/**
 * A runtime exception used to indicate that MAC verification has failed.
 * 
 * <p>
 * This exception is thrown when message authentication for a combined
 * cipher+MAC (e.g. <i>Helix</i>) fails, typically due to a mismatch between the
 * expected MAC and the actual MAC.
 * </p>
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class MessageAuthenticationException extends ProviderException {
    /*
     * The universal serialization version ID for
     * MessageAuthenticationException.
     */
    private static final long serialVersionUID = -2518272027619590751L;

    /* A copy of the MAC the caller expected to be generated. */
    private byte[] expectedMac;

    /* A copy of the MAC that was actually generated. */
    private byte[] actualMac;

    /**
     * Creates a new <tt>MessageAuthenticationException</tt> with the specified
     * detail message.
     * 
     * @param message
     *            the detail message describing this exception
     */
    public MessageAuthenticationException(String message) {
        super(message);
    }

    /**
     * Creates a new <tt>MessageAuthenticationException</tt> with the specified
     * detail message, and saving the expected and actual MACs for reference.
     * 
     * @param message
     *            the detail message describing this exception
     * @param expectedMac
     *            the MAC that was expected to be generated
     * @param actualMac
     *            the MAC that was actually generated
     */
    public MessageAuthenticationException(String message, final byte[] expectedMac, final byte[] actualMac) {
        super(message);
        this.expectedMac = new byte[expectedMac.length];
        System.arraycopy(expectedMac, 0, this.expectedMac, 0, expectedMac.length);
        this.actualMac = new byte[actualMac.length];
        System.arraycopy(actualMac, 0, this.actualMac, 0, actualMac.length);
    }

    /**
     * Creates a new <tt>MessageAuthenticationException</tt> with the specified
     * detail message and cause.
     * 
     * @param message
     *            the detail message describing this exception
     * @param cause
     *            the throwable that caused this exception to be thrown, or
     *            <tt>null</tt> if the cause is nonexistent/unknown
     */
    public MessageAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Returns the MAC that was expected to be generated.
     * 
     * @return a copy of the expected MAC
     */
    public byte[] getExpectedMac() {
        if (expectedMac == null) {
            return null;
        }

        byte[] expectedMacCopy = new byte[expectedMac.length];
        System.arraycopy(expectedMac, 0, expectedMacCopy, 0, expectedMac.length);

        return expectedMacCopy;
    }

    /**
     * Returns the MAC that was actually generated.
     * 
     * @return a copy of the actual MAC
     */
    public byte[] getActualMac() {
        if (actualMac == null) {
            return null;
        }

        byte[] actualMacCopy = new byte[actualMac.length];
        System.arraycopy(actualMac, 0, actualMacCopy, 0, actualMac.length);

        return actualMacCopy;
    }
}
