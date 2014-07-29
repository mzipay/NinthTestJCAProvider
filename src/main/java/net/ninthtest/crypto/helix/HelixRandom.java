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

/**
 * A PRNG that uses the Helix key stream to generate pseudorandom numbers.
 * 
 * @author Matthew Zipay (mattz@ninthtest.net)
 * @version 1.1.0
 */
public class HelixRandom extends Random {
    // the universal serialization version ID for HelixRandom
    private static final long serialVersionUID = -1597295113247853703L;

    /*
     * A specialized Helix primitive that runs the cipher on a counter to
     * product a stream of pseudorandom numbers.
     */
    private class HelixState extends HelixEncryption {
        /*
         * Each step of this counter is used as an input word to the Helix
         * encryption block.
         */
        private int counter;

        /*
         * Creates a new Helix primitive that provides access to the internal
         * state words.
         */
        HelixState(final byte[] key, final byte[] nonce) {
            super(key, nonce);
        }

        /*
         * Returns the next Helix state word, and runs one more block of Helix
         * encryption.
         */
        int nextWord() {
            int word = nextStateWord();

            /*
             * run the cipher on a counter to product a pseudorandom stream
             * (note that Java ints "wrap" automatically, see
             * http://docs.oracle.
             * com/javase/specs/jls/se8/html/jls-4.html#jls-4.2 .2)
             */
            doBlock(counter++);

            return word;
        }
    }

    /* The Helix primitive used to access the state words. */
    private HelixState state;

    /**
     * Creates a new <tt>HelixRandom</tt> using a generated seed.
     */
    public HelixRandom() {
        super();
    }

    /**
     * Creates a new <tt>HelixRandom</tt> using the provided seed.
     *
     * @param seed
     *            the initial seed
     */
    public HelixRandom(final long seed) {
        super(seed);
    }

    /**
     * {@inheritDoc}
     *
     * @param seed
     *            {@inheritDoc}
     * @see java.util.Random#setSeed(long)
     */
    @Override
    public synchronized void setSeed(final long seed) {
        initState(seed);
    }

    /*
     * Initializes a new Helix primitive with a key and nonce that are generated
     * using the seed.
     */
    private void initState(final long seed) {
        Random random = new Random(seed);

        byte[] key = new byte[32];
        random.nextBytes(key);

        byte[] nonce = new byte[16];
        random.nextBytes(nonce);

        state = new HelixState(key, nonce);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Note that the <i>bits</i> argument is ignored by this implementation, as
     * the next word of Helix key stream should already satisfy the contract of
     * {@link Random#next(int)}.
     * </p>
     *
     * @param bits
     *            {@inheritDoc}
     * @return {@inheritDoc}
     * @see java.util.Random#next(int)
     */
    @Override
    protected int next(int bits) {
        return state.nextWord();
    }
}
