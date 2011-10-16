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

package net.ninthtest.security;

import java.text.MessageFormat;
import java.util.ResourceBundle;

/**
 * A utility class for retrieving and formatting localized messages.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public final class Messages {
    /* the resource bundle for NinthTest security/crypto messages */
    private static final ResourceBundle MESSAGES = ResourceBundle.getBundle("net.ninthtest.security.messages");

    /**
     * Returns the localized message associated with <i>key</i>.
     * 
     * @param key the message key
     * @return the localized message, or <i>key</i> itself if the message is not
     *         found
     */
    public static final String getMessage(String key) {
        return getMessage(key, (Object[]) null);
    }

    /**
     * Returns the localized message associated with <i>key</i>, formatted using
     * <i>arguments</i>.
     * 
     * @param key the message key
     * @param arguments values used as positional substitutions into the message
     * @return the formatted, localized message; or <i>key</i> itself if the
     *         message is not found
     */
    public static final String getMessage(String key, Object... arguments) {
        if ((key == null) || key.isEmpty()) {
            throw new IllegalArgumentException(key);
        }

        if (MESSAGES.containsKey(key)) {
            return MessageFormat.format(MESSAGES.getString(key), arguments);
        } else {
            /*
             * the ResourceBundle keys should have descriptive names so
             * that in this case the message at least makes sense
             */
            return key;
        }
    }

    private Messages() {
        /* never instantiated */
    }
}
