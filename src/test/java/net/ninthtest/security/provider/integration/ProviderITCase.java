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

package net.ninthtest.security.provider.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

import net.ninthtest.security.provider.NinthTestProvider;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * The integration test case for {@link NinthTestProvider}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.0
 */
public class ProviderITCase {
    /**
     * Dynamically registers the &quot;NinthTest&quot; security provider if the
     * &quot;ninthtest.provider.register&quot; system property is
     * &quot;true&quot;.
     */
    @BeforeClass
    public static void dynamicRegistration() {
        if (Boolean.getBoolean("ninthtest.provider.register")) {
            int preference = Security.addProvider(new NinthTestProvider());
            assertTrue(preference != -1);
        }
    }

    /**
     * Asserts that the &quot;NinthTest&quot; security provider has the expected
     * identification attributes.
     */
    @Test
    public void canObtainTheProvider() {
        Provider provider = Security.getProvider("NinthTest");
        assertNotNull(provider);
        assertEquals("NinthTest", provider.getName());
        assertEquals(1.0, provider.getVersion(), 0.0000001);
        assertEquals(NinthTestProvider.INFO, provider.getInfo());
    }

    /**
     * Asserts that the &quot;NinthTest&quot; security provider has the expected
     * Helix services.
     * 
     * @throws Exception if the test fails
     */
    @Test
    public void confirmHelixServices() throws Exception {
        Provider provider = Security.getProvider("NinthTest");
        Set<Provider.Service> services = provider.getServices();
        assertEquals(5, services.size());

        for (Provider.Service service : services) {
            assertEquals("Helix", service.getAlgorithm());
            assertEquals("NinthTest", service.getProvider().getName());

            String serviceType = service.getType();
            if ("Cipher".equals(serviceType)) {
                assertEquals("net.ninthtest.crypto.provider.helix.HelixCipher", service.getClassName());
                Cipher.getInstance("Helix", provider);
            } else if ("Mac".equals(serviceType)) {
                assertEquals("net.ninthtest.crypto.provider.helix.HelixMac", service.getClassName());
                Mac.getInstance("Helix", provider);
            } else if ("SecretKeyFactory".equals(serviceType)) {
                assertEquals("net.ninthtest.crypto.provider.helix.HelixSecretKeyFactory", service.getClassName());
                SecretKeyFactory.getInstance("Helix", provider);
            } else if ("AlgorithmParameters".equals(serviceType)) {
                assertEquals("net.ninthtest.crypto.provider.helix.HelixAlgorithmParameters", service.getClassName());
                AlgorithmParameters.getInstance("Helix", provider);
            } else if ("KeyGenerator".equals(serviceType)) {
                assertEquals("net.ninthtest.crypto.provider.helix.HelixKeyGenerator", service.getClassName());
                KeyGenerator.getInstance("Helix", provider);
            } else {
                fail("Unexpected: " + serviceType + " -> " + service.getClassName());
            }
        }
    }
}
