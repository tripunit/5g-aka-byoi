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

package ca.uwaterloo.fivegakabyoi.ueemulator;

import java.io.UnsupportedEncodingException;
import java.lang.StringBuilder;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class OAuthUtils
{
    private static final SecureRandom sr = new SecureRandom();

    static public String randomString(int bytes)
    {
        byte[] random = new byte[bytes];

        sr.nextBytes(random);

        return Base64.getEncoder().encodeToString(random);
    }

    static public Map<String, String> parseQuery(String query)
    {
        try {
            HashMap<String, String> params = new HashMap<>();
            String[]                pairs  = query.split("&");

            for (String pair : pairs) {
                int equals = pair.indexOf("=");

                params.put(
                    URLDecoder.decode(pair.substring(0, equals), "UTF-8"),
                    URLDecoder.decode(pair.substring(equals + 1), "UTF-8")
                );
            }

            return params;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 is not supported (should never happen)", e);
        }
    }

    static public String unparseQuery(HashMap<String, String> params)
    {
        try {
            StringBuilder sb = new StringBuilder();

            for (Map.Entry<String, String> param : params.entrySet()) {
                String name  = URLEncoder.encode(param.getKey(),   "UTF-8");
                String value = URLEncoder.encode(param.getValue(), "UTF-8");

                sb.append('&');
                sb.append(name);
                sb.append('=');
                sb.append(value);
            }

            return sb.substring(1);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 is not supported (should never happen)", e);
        }
    }
}
