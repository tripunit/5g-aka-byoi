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

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class Supi
{
    public static final String SUPI_TYPE_IMSI = "0";
    public static final String SUPI_TYPE_NSI  = "1";

    private static final Map<String, SupiFactory> factories;

    static {
        Map<String, SupiFactory> m = new HashMap<>();

        m.put(SUPI_TYPE_IMSI, new ImsiSupiFactory());
        m.put(SUPI_TYPE_NSI,  new NsiSupiFactory());

        factories = Collections.unmodifiableMap(m);
    }

    public abstract String getType();
    public abstract String getUserId();
    public abstract String getHnId();

    public byte[] encodeUserId(boolean nullScheme)
    {
        return Utf8.str2bytes(getUserId());
    }

    public static SupiFactory getFactory(String supiType) throws UnknownSupiTypeException
    {
        SupiFactory f = factories.get(supiType);

        if (f == null)
            throw new UnknownSupiTypeException(String.format("Unknown SUPI type: %s", supiType));

        return f;
    }
}
