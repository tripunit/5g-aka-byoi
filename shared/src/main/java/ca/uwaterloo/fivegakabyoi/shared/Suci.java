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

import java.lang.System;
import java.util.Optional;
import java.util.regex.Pattern;

import org.apache.commons.lang3.tuple.ImmutablePair;

public class Suci
{
    public interface EncryptionProfileMap
    {
        public Optional<SuciEncryptionProfile> getEncryptionProfile(
            String schemeId,
            String hnPubkeyId
        );
    }

    private enum SuciField
    {
        SUPI_TYPE     ("SUPI Type",                  "[0-7]"                                         ),
        HN_ID         ("Home Network Identifier",    null                                            ),
        ROUTING_IND   ("Rounting Indicator",         "[0-9]{1,4}"                                    ),
        SCHEME_ID     ("Protection Scheme ID",       "[0-9a-fA-F]"                                   ), // One hex digit (even though other fields are decimal)
        HN_PUBKEY_ID  ("Home Network Public Key ID", "[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]"), // 0-255
        SCHEME_OUTPUT ("Scheme Output",              null                                            );

        public String  name;
        public Pattern regex;

        private SuciField(String name, String regex)
        {
            this.name  = name;
            this.regex = regex == null ? null : Pattern.compile(regex);
        }
    }

    private Supi   supi;
    private String routingInd;

    public Suci(Supi supi, String routingInd) throws FormatException
    {
        setSupi       (supi);
        setRoutingInd (routingInd);
    }

    public String getRoutingInd() { return routingInd; }
    public Supi   getSupi()       { return supi;       }

    public void setRoutingInd(String routingInd) throws FormatException
    {
        validateField(SuciField.ROUTING_IND, routingInd);

        this.routingInd = routingInd;
    }

    public void setSupi(Supi supi)
    {
        this.supi = supi;
    }

    public String encrypt(SuciEncryptionProfile profile, String hnPubkeyId)
    throws FormatException, SuciEncryptionException
    {
        String schemeId = profile.getProtectionSchemeId();

        validateField(SuciField.SCHEME_ID,    schemeId  );
        validateField(SuciField.HN_PUBKEY_ID, hnPubkeyId);

        validateSchemePubkeyCompatibility(schemeId, hnPubkeyId);

        byte[] schemeInput = supi.encodeUserId(schemeId.equals("0"));

        String schemeOutput = profile.encrypt(schemeInput);

        StringBuilder suci = new StringBuilder();

        suci.append(supi.getType());
        suci.append("-");
        suci.append(supi.getHnId());
        suci.append("-");
        suci.append(routingInd);
        suci.append("-");
        suci.append(schemeId);
        suci.append("-");
        suci.append(hnPubkeyId);
        suci.append("-");
        suci.append(schemeOutput);

        return suci.toString();
    }

    public static Suci fromEncrypted(String suci, EncryptionProfileMap profiles)
    throws FormatException, SuciEncryptionException
    {
        String[] fields = parseSuci(suci);

        String schemeId   = fields[SuciField.SCHEME_ID   .ordinal()];
        String hnPubkeyId = fields[SuciField.HN_PUBKEY_ID.ordinal()];

        validateSchemePubkeyCompatibility(schemeId, hnPubkeyId);

        SuciEncryptionProfile profile = profiles.getEncryptionProfile(
                schemeId,
                hnPubkeyId
            ).orElseThrow(() -> new FormatException(
                    String.format(
                        "No public key found for Protection Scheme ID %s with Home Network Public Key ID %s",
                        schemeId,
                        hnPubkeyId
                    )
                )
            );

        Supi supi;

        try {
            String      supiType    = fields[SuciField.SUPI_TYPE.ordinal()];
            SupiFactory supiFactory = Supi.getFactory(supiType);

            String userId = supiFactory.decodeUserId(
                profile.decrypt(fields[SuciField.SCHEME_OUTPUT.ordinal()]),
                schemeId.equals("0")
            );

            supi = supiFactory.buildSupi(userId, fields[SuciField.HN_ID.ordinal()]);
        } catch (UnknownSupiTypeException e) {
            throw new FormatException(e);
        }

        return new Suci(supi, fields[SuciField.ROUTING_IND.ordinal()]);
    }

    public static ImmutablePair<String, String> getRoutingInfo(String suci)
    throws FormatException
    {
        String[] fields = parseSuci(suci);

        SupiFactory supiFactory;

        try {
            supiFactory = Supi.getFactory(fields[SuciField.SUPI_TYPE.ordinal()]);
        } catch (UnknownSupiTypeException e) {
            throw new FormatException(e);
        }

        String hnId = fields[SuciField.HN_ID.ordinal()];

        if (!supiFactory.isValidHnId(hnId))
            throw new FormatException(String.format("Invalid HN ID: %s", hnId));

        return ImmutablePair.of(
            hnId,
            fields[SuciField.ROUTING_IND.ordinal()]
        );
    }

    private static void validateField(SuciField field, String value)
    throws FormatException
    {
        if (field.regex != null && !field.regex.matcher(value).matches())
            throw new FormatException(
                String.format(
                    "Invalid %s: %s",
                    field.name,
                    value
                )
            );
    }

    private static void validateSchemePubkeyCompatibility(String schemeId, String hnPubkeyId)
    throws FormatException
    {
        if (schemeId.equals("0") && !hnPubkeyId.equals("0"))
            throw new FormatException("If the Null Scheme is used, the Home Network Public Key ID must be 0");

        if (!schemeId.equals("0") && hnPubkeyId.equals("0"))
            throw new FormatException("If the Null Scheme is not used, the Home Network Public Key ID cannot be 0");
    }

    private static String[] parseSuci(String suci) throws FormatException
    {
        String[]    fields         = suci.split("-");
        SuciField[] expectedFields = SuciField.values();

        if (fields.length < expectedFields.length)
            throw new FormatException(
                String.format(
                    "Unexpected number of fields in SUCI (expected %d, got %d): %s",
                    expectedFields.length,
                    fields.length,
                    suci
                )
            );

        if (fields.length > expectedFields.length) {
            // The NSI may contain dashes, since they are allowed by RFC7542,
            // so the initial split on "-" may have broken up the NSI. If there
            // are extra fields we assume this has happened and reconstruct
            // the NSI. This means there is no way to detect a genuinely
            // misformatted SUCI with extra fields. Such as SUCI will be
            // rejected at a later stage based on invalid field content.

            String[] newFields = new String[expectedFields.length];

            int hnIdIdx = SuciField.HN_ID.ordinal();

            System.arraycopy(fields, 0, newFields, 0, hnIdIdx);

            System.arraycopy(
                fields,
                hnIdIdx + (fields.length - expectedFields.length) + 1,
                newFields,
                hnIdIdx + 1,
                expectedFields.length - hnIdIdx - 1
            );

            StringBuilder hnId = new StringBuilder();

            hnId.append(fields[hnIdIdx]);

            for (int i = 0; i < fields.length - expectedFields.length; i++) {
                hnId.append("-");
                hnId.append(fields[hnIdIdx + 1 + i]);
            }

            newFields[hnIdIdx] = hnId.toString();

            fields = newFields;
        }

        for (int i = 0; i < expectedFields.length; i++)
            validateField(expectedFields[i], fields[i]);

        return fields;
    }
}
