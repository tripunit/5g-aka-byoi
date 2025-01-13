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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.openssl.PEMParser;

public class X25519Loader
{
    public static X25519PrivateKeyParameters loadPrivateKey(InputStream input)
    throws X25519LoadingException
    {
        PrivateKeyInfo privateKeyInfo;

        try {
            InputStreamReader isr = new InputStreamReader(input);
            BufferedReader    br  = new BufferedReader(isr);
            PEMParser         pem = new PEMParser(br);

            privateKeyInfo = (PrivateKeyInfo) pem.readObject();
        } catch (IOException e) {
            throw new X25519LoadingException(e);
        } catch (ClassCastException e) {
            throw new X25519LoadingException("Unable to load private key: unexpected PEM object");
        }

        String algId = privateKeyInfo.getPrivateKeyAlgorithm()
            .getAlgorithm()
            .getId();

        if (!algId.equals("1.3.101.110")) {
            throw new X25519LoadingException(
                String.format(
                    "Unable to load private key: unexpected OID %s (only X25519 keys are supported)",
                    algId
                )
            );
        }

        try {
            ASN1OctetString privateKeyOs    = (ASN1OctetString) privateKeyInfo.parsePrivateKey();
            byte[]          privateKeyBytes = privateKeyOs.getOctets();

            return new X25519PrivateKeyParameters(privateKeyBytes);
        } catch (IOException | IllegalArgumentException e) {
            throw new X25519LoadingException("Unable to load private key: error while parsing", e);
        }
    }
}
