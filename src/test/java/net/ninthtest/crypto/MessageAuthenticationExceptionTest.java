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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

import net.ninthtest.crypto.helix.HelixTestVectors;
import org.junit.Test;

/**
 * The unit test case for {@link MessageAuthenticationException}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class MessageAuthenticationExceptionTest implements HelixTestVectors {
    /**
     * Asserts that a {@link MessageAuthenticationException} has the expected
     * message.
     */
    @Test
    public void initWithMessage() {
        MessageAuthenticationException ex =
                new MessageAuthenticationException("testMessageAuthenticationException_String");

        assertEquals("testMessageAuthenticationException_String", ex.getMessage());
        assertNull(ex.getCause());
        assertNull(ex.getExpectedMac());
        assertNull(ex.getActualMac());
    }

    /**
     * Asserts that a {@link MessageAuthenticationException} has the expected
     * message and MACs.
     */
    @Test
    public void initWithMessageAndByteArrays() {
        byte[] expected = new byte[16];
        Arrays.fill(expected, (byte) 1);
        byte[] actual = new byte[16];
        Arrays.fill(actual, (byte) 2);

        MessageAuthenticationException ex =
                new MessageAuthenticationException("testMessageAuthenticationException_String_byteArray_byteArray",
                        expected, actual);

        assertEquals("testMessageAuthenticationException_String_byteArray_byteArray", ex.getMessage());
        assertNull(ex.getCause());
        assertArrayEquals(expected, ex.getExpectedMac());
        assertArrayEquals(actual, ex.getActualMac());
    }

    /**
     * Asserts that the MACs stored by a {@link MessageAuthenticationException}
     * cannot be modified by reference.
     */
    @Test
    public void macByteArraysAreNotModifiable() {
        byte[] expected = new byte[16];
        byte[] actual = new byte[16];

        MessageAuthenticationException ex = new MessageAuthenticationException(null, expected, actual);
        byte[] expectedCopy = ex.getExpectedMac();
        byte[] actualCopy = ex.getActualMac();
        expectedCopy[0] = actualCopy[0] = (byte) 1;

        assertFalse(Arrays.equals(expectedCopy, ex.getExpectedMac()));
        assertFalse(Arrays.equals(actualCopy, ex.getActualMac()));
    }

    /**
     * Asserts that a {@link MessageAuthenticationException} has the expected
     * message and cause.
     */
    @Test
    public void initWithMessageAndThrowable() {
        MessageAuthenticationException ex =
                new MessageAuthenticationException("testMessageAuthenticationException_String_Throwable",
                        new Exception("wrapped"));

        assertEquals("testMessageAuthenticationException_String_Throwable", ex.getMessage());
        assertEquals("wrapped", ex.getCause().getMessage());
        assertNull(ex.getExpectedMac());
        assertNull(ex.getActualMac());
    }
}
