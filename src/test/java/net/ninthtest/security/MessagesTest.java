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

package net.ninthtest.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import org.junit.Test;

/**
 * The unit test case for {@link Messages}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class MessagesTest {
    /* tests for Messages#getMessage(String) */

    /**
     * Asserts that {@link Messages#getMessage(String)} fails if the key is
     * <tt>null</tt>.
     */
    @Test(expected = IllegalArgumentException.class)
    public void getMessageFailsOnNullKey() {
        Messages.getMessage(null);
    }

    /**
     * Asserts that {@link Messages#getMessage(String)} fails if the key is the
     * empty string.
     */
    @Test(expected = IllegalArgumentException.class)
    public void getMessageFailsOnEmptyKey() {
        Messages.getMessage("");
    }

    /**
     * Asserts that {@link Messages#getMessage(String)} returns the key itself
     * if the key is not in the resource bundle.
     */
    @Test
    public void getMessageReturnsKeyWhenKeyNotFound() {
        assertEquals("message.key.not_found", Messages.getMessage("message.key.not_found"));
    }

    /**
     * Asserts that {@link Messages#getMessage(String)} returns a localized
     * message when the key is found in the resource bundle.
     */
    @Test
    public void getMessageReturnsMessageWhenKeyFound() {
        assertNotSame("error.not_signed", Messages.getMessage("error.not_signed"));
    }

    /* tests for Messages#getMessage(String, Object...) */

    /**
     * Asserts that {@link Messages#getMessage(String, Object...)} fails if the
     * key is <tt>null</tt>.
     */
    @Test(expected = IllegalArgumentException.class)
    public void getMessageWithSubsFailsOnNullKey() {
        Messages.getMessage(null, (Object[]) null);
    }

    /**
     * Asserts that {@link Messages#getMessage(String, Object...)} fails if the
     * key is the empty string.
     */
    @Test(expected = IllegalArgumentException.class)
    public void getMessageWithSubsFailsOnEmptyKey() {
        Messages.getMessage("", (Object[]) null);
    }

    /**
     * Asserts that {@link Messages#getMessage(String, Object...)} returns the
     * key itself if the key is not in the resource bundle.
     */
    @Test
    public void getMessageWithSubsReturnsKeyWhenKeyNotFound() {
        assertEquals("message.key.not_found", Messages.getMessage("message.key.not_found", (Object[]) null));
    }

    /**
     * Asserts that {@link Messages#getMessage(String, Object...)} returns a
     * localized message when the key is found in the resource bundle.
     */
    @Test
    public void getMessageWithSubsReturnsMessageWhenKeyFound() {
        assertNotSame("error.failed_to_create_key",
                Messages.getMessage("error.failed_to_create_key", "Blowfish", "SECRET_KEY"));
    }
}
