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

package net.ninthtest.crypto.helix;

import java.util.Random;

import org.junit.Test;

/**
 * The unit test case for {@link HelixRandom}.
 *
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixRandomTest {
    /**
     * Asserts that {@link HelixRandom} can be instantiated without an argument.
     */
    @Test
    public void initNoArg() {
        @SuppressWarnings("unused")
        Random random = new HelixRandom();
    }

    /**
     * Asserts that {@link HelixRandom} can be instantiated with an explicit
     * initial seed.
     */
    @Test
    public void initWithSeed() {
        @SuppressWarnings("unused")
        Random random = new HelixRandom(System.currentTimeMillis());
    }

    /**
     * Asserts that {@link HelixRandom#setSeed(long)} can be used to set an
     * explicit initial seed.
     */
    @Test
    public void setSeed() {
        Random random = new HelixRandom();
        random.setSeed(System.currentTimeMillis());
    }

    /**
     * Asserts that {@link HelixRandom#next(int)} returns pseudorandom numbers.
     */
    @Test
    public void nextBits() {
        Random random = new HelixRandom();
        random.nextBoolean();
        random.nextBytes(new byte[7]);
        random.nextDouble();
        random.nextFloat();
        random.nextGaussian();
        random.nextInt();
        random.nextInt(7);
        random.nextLong();
    }
}
