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

package net.ninthtest.security.provider.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

import net.ninthtest.crypto.provider.helix.HelixAlgorithmParameters;
import net.ninthtest.crypto.provider.helix.HelixCipher;
import net.ninthtest.crypto.provider.helix.HelixKeyGenerator;
import net.ninthtest.crypto.provider.helix.HelixMac;
import net.ninthtest.crypto.provider.helix.HelixSecretKeyFactory;
import net.ninthtest.crypto.provider.helix.HelixSecureRandom;
import net.ninthtest.security.provider.NinthTestProvider;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * The integration test case for {@link NinthTestProvider}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class ProviderITCase {
    /**
     * Dynamically registers the NinthTest security provider if the
     * "ninthtest.provider.register" system property is <i>true</i>.
     */
    @BeforeClass
    public static void dynamicRegistration() {
        if (Boolean.getBoolean("ninthtest.provider.register")) {
            int preference = Security.addProvider(new NinthTestProvider());
            assertTrue(preference != -1);
        }
    }

    /**
     * Asserts that the NinthTest security provider has the expected
     * identification attributes.
     */
    @Test
    public void canObtainTheProvider() {
        Provider provider = Security.getProvider("NinthTest");
        assertNotNull(provider);
        assertEquals(NinthTestProvider.NAME, provider.getName());
        assertEquals(NinthTestProvider.VERSION, provider.getVersion(), 0.0000001);
        assertEquals(NinthTestProvider.INFO, provider.getInfo());
    }

    /**
     * Asserts that the NinthTest security provider supports the expected number
     * of services.
     */
    @Test
    public void confirmTotalServices() {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        assertNotNull(provider);
        Set<Service> services = provider.getServices();
        assertEquals(6, services.size());
    }

    /**
     * Asserts that the NinthTest provider supports the Helix Cipher service.
     *
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void confirmHelixCipherService() throws Exception {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        Service service = provider.getService("Cipher", NinthTestProvider.HELIX);
        assertNotNull(service);
        assertEquals(HelixCipher.class.getName(), service.getClassName());
        Cipher.getInstance(NinthTestProvider.HELIX, NinthTestProvider.NAME);
    }

    /**
     * Asserts that the NinthTest provider supports the Helix Mac service.
     *
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void confirmHelixMacService() throws Exception {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        Service service = provider.getService("Mac", NinthTestProvider.HELIX);
        assertNotNull(service);
        assertEquals(HelixMac.class.getName(), service.getClassName());
        Mac.getInstance(NinthTestProvider.HELIX, NinthTestProvider.NAME);
    }

    /**
     * Asserts that the NinthTest provider supports the Helix SecureRandom
     * service.
     *
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void confirmHelixSecureRandomService() throws Exception {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        Service service = provider.getService("SecureRandom", NinthTestProvider.HELIX);
        assertNotNull(service);
        assertEquals(HelixSecureRandom.class.getName(), service.getClassName());
        SecureRandom.getInstance(NinthTestProvider.HELIX, NinthTestProvider.NAME);
    }

    /**
     * Asserts that the NinthTest provider supports the Helix SecretKeyFactory
     * service.
     *
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void confirmHelixSecretKeyFactoryService() throws Exception {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        Service service = provider.getService("SecretKeyFactory", NinthTestProvider.HELIX);
        assertNotNull(service);
        assertEquals(HelixSecretKeyFactory.class.getName(), service.getClassName());
        SecretKeyFactory.getInstance(NinthTestProvider.HELIX, NinthTestProvider.NAME);
    }

    /**
     * Asserts that the NinthTest provider supports the Helix
     * AlgorithmParameters service.
     *
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void confirmHelixAlgorithmParametersService() throws Exception {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        Service service = provider.getService("AlgorithmParameters", NinthTestProvider.HELIX);
        assertNotNull(service);
        assertEquals(HelixAlgorithmParameters.class.getName(), service.getClassName());
        AlgorithmParameters.getInstance(NinthTestProvider.HELIX, NinthTestProvider.NAME);
    }

    /**
     * Asserts that the NinthTest provider supports the Helix KeyGenerator
     * service.
     *
     * @throws Exception
     *             if the test fails
     */
    @Test
    public void confirmHelixKeyGeneratorService() throws Exception {
        Provider provider = Security.getProvider(NinthTestProvider.NAME);
        Service service = provider.getService("KeyGenerator", NinthTestProvider.HELIX);
        assertNotNull(service);
        assertEquals(HelixKeyGenerator.class.getName(), service.getClassName());
        KeyGenerator.getInstance(NinthTestProvider.HELIX, NinthTestProvider.NAME);
    }
}
