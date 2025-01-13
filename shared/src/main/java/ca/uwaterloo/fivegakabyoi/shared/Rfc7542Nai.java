// Copyright (c) 2023-2024 Julian Parkin
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class Rfc7542Nai
{
    // Generated regexes; see util/rfc7452regex.py
    private static final Pattern RFC_7542_NAI_REGEX      = Pattern.compile("(?<usernameOnly>(?:[a-zA-Z0-9!#$%&'\\*\\+\\-/=\\?\\^_`{\\|}~\\x{80}-\\x{10FFFF}])+(?:\\.(?:[a-zA-Z0-9!#$%&'\\*\\+\\-/=\\?\\^_`{\\|}~\\x{80}-\\x{10FFFF}])+)*)|@(?<realmOnly>(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}](?:(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}]|-)*[a-zA-Z0-9\\x{80}-\\x{10FFFF}])*\\.)+[a-zA-Z0-9\\x{80}-\\x{10FFFF}](?:(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}]|-)*[a-zA-Z0-9\\x{80}-\\x{10FFFF}])*)|(?<username>(?:[a-zA-Z0-9!#$%&'\\*\\+\\-/=\\?\\^_`{\\|}~\\x{80}-\\x{10FFFF}])+(?:\\.(?:[a-zA-Z0-9!#$%&'\\*\\+\\-/=\\?\\^_`{\\|}~\\x{80}-\\x{10FFFF}])+)*)@(?<realm>(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}](?:(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}]|-)*[a-zA-Z0-9\\x{80}-\\x{10FFFF}])*\\.)+[a-zA-Z0-9\\x{80}-\\x{10FFFF}](?:(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}]|-)*[a-zA-Z0-9\\x{80}-\\x{10FFFF}])*)");
    private static final Pattern RFC_7542_USERNAME_REGEX = Pattern.compile("(?:[a-zA-Z0-9!#$%&'\\*\\+\\-/=\\?\\^_`{\\|}~\\x{80}-\\x{10FFFF}])+(?:\\.(?:[a-zA-Z0-9!#$%&'\\*\\+\\-/=\\?\\^_`{\\|}~\\x{80}-\\x{10FFFF}])+)*");
    private static final Pattern RFC_7542_REALM_REGEX    = Pattern.compile("(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}](?:(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}]|-)*[a-zA-Z0-9\\x{80}-\\x{10FFFF}])*\\.)+[a-zA-Z0-9\\x{80}-\\x{10FFFF}](?:(?:[a-zA-Z0-9\\x{80}-\\x{10FFFF}]|-)*[a-zA-Z0-9\\x{80}-\\x{10FFFF}])*");

    private String username;
    private String realm;

    public Rfc7542Nai(String nai) throws FormatException
    {
        Matcher m = RFC_7542_NAI_REGEX.matcher(nai);

        if (m.matches()) {
            String groupUsernameOnly = m.group("usernameOnly");
            String groupRealmOnly    = m.group("realmOnly");
            String groupUsername     = m.group("username");
            String groupRealm        = m.group("realm");

            if (groupUsernameOnly != null) {
                assert groupRealmOnly == null;
                assert groupUsername  == null;
                assert groupRealm     == null;

                username = groupUsernameOnly;
                realm    = "";
            } else if (groupRealmOnly != null) {
                assert groupUsernameOnly == null;
                assert groupUsername     == null;
                assert groupRealm        == null;

                username = "";
                realm    = groupRealmOnly;
            } else {
                assert groupUsernameOnly == null;
                assert groupRealmOnly    == null;

                username = groupUsername;
                realm    = groupRealm;
            }
        } else {
            throw new FormatException(String.format("Not a valid NAI: %s", nai));
        }
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || obj.getClass() != this.getClass())
            return false;

        if (this == obj)
            return true;

        Rfc7542Nai n = (Rfc7542Nai) obj;

        return new EqualsBuilder()
            .append(realm,    n.realm   )
            .append(username, n.username)
            .isEquals();
    }

    @Override
    public int hashCode()
    {
        return new HashCodeBuilder(29399, 44267)
            .append(realm   )
            .append(username)
            .toHashCode();
    }

    public String getRealm()    { return realm;    }
    public String getUsername() { return username; }

    public void setUsername(String username) throws FormatException
    {
        Matcher m = RFC_7542_USERNAME_REGEX.matcher(username);

        if (!m.matches() && !username.isEmpty())
            throw new FormatException(String.format("Not a valid username: %s", username));

        this.username = username;
    }

    public void setRealm(String realm) throws FormatException
    {
        Matcher m = RFC_7542_REALM_REGEX.matcher(realm);

        if (!m.matches() && !realm.isEmpty())
            throw new FormatException(String.format("Not a valid realm: %s", realm));

        this.realm = realm;
    }

    // Can't implement Object.toString() since this may throw
    public String toNaiString() throws FormatException
    {
        if (!username.isEmpty() && !realm.isEmpty()) {
            return username + "@" + realm;
        } else if (!username.isEmpty()) {
            return username;
        } else if (!realm.isEmpty()) {
            return "@" + realm;
        } else {
            throw new FormatException("At least one of username or realm must be present in a valid NAI");
        }
    }
}
