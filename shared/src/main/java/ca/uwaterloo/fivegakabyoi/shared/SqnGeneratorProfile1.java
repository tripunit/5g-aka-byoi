// Copyright (c) 2024 Julian Parkin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package ca.uwaterloo.fivegakabyoi.shared;

import java.lang.IllegalArgumentException;

// SQN generator implementing Profile 1 from Annex C.3.1 of 3GPP TS 33.102

public class SqnGeneratorProfile1 implements SqnGenerator
{
    public interface GlobalClock
    {
        public long getTime();
    }

    private static final long SEQ2_SHIFT = 5L;
    private static final long SEQ2_MASK  = ((1L << 24L) - 1L) << SEQ2_SHIFT;
    private static final long SEQ1_SHIFT = SEQ2_SHIFT + 24L;
    private static final long SEQ1_MASK  = ((1L << 19L) - 1L) << SEQ1_SHIFT;
    private static final long P          = 1L << 24L;
    private static final long D          = 1L << 16L;

    private final GlobalClock clock;
    private       long        sqn;

    public SqnGeneratorProfile1(GlobalClock clock, long curSqn)
    {
        if (curSqn > MAX_SQN)
            throw new IllegalArgumentException("curSqn is too large to be a valid SQN");

        this.clock = clock;
        this.sqn   = curSqn;
    }

    public long getInitialSqn()
    {
        long glc = clock.getTime() & (P - 1);

        return glc << SEQ2_SHIFT;
    }

    @Override
    public long generate()
    throws SqnGenerationException
    {
        sqn = getNextSqn();

        return sqn;
    }

    @Override
    public long resync(long sqnUe)
    throws SqnGenerationException
    {
        if (sqnUe > MAX_SQN)
            throw new IllegalArgumentException("sqnUe is too large to be a valid SQN");

        sqn = getNextSqn();

        if (sqnUe > sqn)
            sqn = sqnUe;

        return sqn;
    }

    private long getNextSqn()
    throws SqnGenerationException
    {
        long seq1 = (sqn >> SEQ1_SHIFT) & SEQ1_MASK;
        long seq2 = (sqn >> SEQ2_SHIFT) & SEQ2_MASK;
        long glc  = clock.getTime() & (P - 1);

        long nextSqn;

        if (seq2 < glc && glc < seq2 + P - (D - 1))
            nextSqn = (seq1 << SEQ1_SHIFT) | (glc << SEQ2_SHIFT);
        else if ((glc <= seq2 && seq2 < glc + (D - 1)) || (seq2 + P - (D - 1) <= glc))
            nextSqn = sqn + (1 << SEQ2_SHIFT);
        else
            nextSqn = ((seq1 + 1) << SEQ1_SHIFT) | (glc << SEQ2_SHIFT);

        if (nextSqn > MAX_SQN)
            throw new SqnGenerationException("SQN has reached its maximum value");

        return nextSqn;
    }
}
