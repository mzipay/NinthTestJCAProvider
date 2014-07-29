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

import static org.junit.Assert.assertEquals;

import java.security.Provider;
import java.util.Set;

import net.ninthtest.crypto.provider.helix.HelixAlgorithmParameters;
import net.ninthtest.crypto.provider.helix.HelixCipher;
import net.ninthtest.crypto.provider.helix.HelixKeyGenerator;
import net.ninthtest.crypto.provider.helix.HelixMac;
import net.ninthtest.crypto.provider.helix.HelixSecretKeyFactory;
import net.ninthtest.crypto.provider.helix.HelixSecureRandom;
import org.junit.Before;
import org.junit.Test;

/**
 * The unit test case for {@link NinthTestProvider}.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class NinthTestProviderTest {
    /* The instance used by unit tests. */
    private Provider provider;

    /**
     * Creates a {@link NinthTestProvider} instance for testing.
     */
    @Before
    public void createNinthTestProvider() {
        provider = new NinthTestProvider();
    }

    /**
     * Asserts that {@link NinthTestProvider#getName()} returns the provider
     * name.
     */
    @Test
    public void getNameReturnsName() {
        assertEquals(NinthTestProvider.NAME, provider.getName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getVersion()} returns the provider
     * version.
     */
    @Test
    public void getVersionReturnsVersion() {
        assertEquals(NinthTestProvider.VERSION, provider.getVersion(), 0.0000001);
    }

    /**
     * Asserts that {@link NinthTestProvider#getInfo()} returns the provider
     * description.
     */
    @Test
    public void getInfoReturnsDescription() {
        assertEquals(NinthTestProvider.INFO, provider.getInfo());
    }

    /**
     * Asserts that {@link NinthTestProvider#getService(String, String)} returns
     * the Helix Cipher service.
     */
    @Test
    public void getServiceReturnsHelixCipher() {
        Provider.Service service = provider.getService("Cipher", NinthTestProvider.HELIX);

        assertEquals(HelixCipher.class.getName(), service.getClassName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getService(String, String)} returns
     * the Helix Mac service.
     */
    @Test
    public void getServiceReturnsHelixMac() {
        Provider.Service service = provider.getService("Mac", NinthTestProvider.HELIX);

        assertEquals(HelixMac.class.getName(), service.getClassName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getService(String, String)} returns
     * the Helix SecureRandom service.
     */
    @Test
    public void getServiceReturnsHelixSecureRandom() {
        Provider.Service service = provider.getService("SecureRandom", NinthTestProvider.HELIX);

        assertEquals(HelixSecureRandom.class.getName(), service.getClassName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getService(String, String)} returns
     * the Helix SecretKeyFactory service.
     */
    @Test
    public void getServiceReturnsHelixSecretKeyFactory() {
        Provider.Service service = provider.getService("SecretKeyFactory", NinthTestProvider.HELIX);

        assertEquals(HelixSecretKeyFactory.class.getName(), service.getClassName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getService(String, String)} returns
     * the Helix AlgorithmParameters service.
     */
    @Test
    public void getServiceReturnsHelixAlgorithmParameters() {
        Provider.Service service = provider.getService("AlgorithmParameters", NinthTestProvider.HELIX);

        assertEquals(HelixAlgorithmParameters.class.getName(), service.getClassName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getService(String, String)} returns
     * the Helix KeyGenerator service.
     */
    @Test
    public void getServiceReturnsHelixKeyGenerator() {
        Provider.Service service = provider.getService("KeyGenerator", NinthTestProvider.HELIX);

        assertEquals(HelixKeyGenerator.class.getName(), service.getClassName());
    }

    /**
     * Asserts that {@link NinthTestProvider#getServices()} returns the expected
     * number of services.
     */
    @Test
    public void testGetServices() {
        Set<Provider.Service> services = provider.getServices();

        assertEquals(6, services.size());
    }
}
