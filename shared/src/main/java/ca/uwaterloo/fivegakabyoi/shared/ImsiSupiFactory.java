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

import org.apache.commons.lang3.tuple.ImmutablePair;

public class ImsiSupiFactory extends SupiFactory
{
    @Override
    public Supi buildSupi(String userId, String hnId) throws FormatException
    {
        ImmutablePair<String, String> mccMnc = splitMccMnc(hnId);

        return new ImsiSupi(mccMnc.getLeft(), mccMnc.getRight(), userId);
    }

    @Override
    public boolean isValidHnId(String hnId)
    {
        ImmutablePair<String, String> mccMnc;

        try {
            mccMnc = splitMccMnc(hnId);
        } catch (FormatException e) {
            return false;
        }

        return ImsiSupi.isValidMcc(mccMnc.getLeft()) && ImsiSupi.isValidMnc(mccMnc.getRight());
    }

    @Override
    public String decodeUserId(byte[] encoded, boolean nullScheme) throws FormatException
    {
        // IMSI was not encoded if the null scheme was used
        if (nullScheme)
            return super.decodeUserId(encoded, nullScheme);

        int length;

        if ((encoded[encoded.length - 1] & 0xF0) == 0xF0)
            length = (encoded.length << 1) - 1;
        else
            length = encoded.length << 1;

        char[] chars = new char[length];

        for (int i = 0; i < length; i++) {
            int digit = (encoded[i >> 1] >> ((i & 1) << 2)) & 0x0F;

            if (digit > 9)
                throw new FormatException("MSIN is not coded as valid BCD");

            chars[i] = (char) ('0' + digit);
        }

        return new String(chars);
    }

    private static ImmutablePair<String, String> splitMccMnc(String hnId) throws FormatException
    {
        String[] fields = hnId.split("-");

        if (fields.length != 2)
            throw new FormatException(String.format("Invalid HN ID for IMSI SUPI: %s", hnId));

        return ImmutablePair.of(fields[0], fields[1]);
    }
}
