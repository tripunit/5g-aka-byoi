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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class GoogleOAuthSession implements OAuthSession
{
    private static final ObjectMapper mapper = new ObjectMapper();

    private final GoogleOAuthProvider provider;
    private final String              nonce;
    private final String              state;

    private       String              redirectUri;
    private       String              authenticationCode;
    private       String              subscriber;

    public GoogleOAuthSession(GoogleOAuthProvider provider)
    {
        this.provider = provider;

        nonce = OAuthUtils.randomString(16);
        state = OAuthUtils.randomString(16);
    }

    @Override
    public String getAuthenticationRequestUrl(String redirectUri)
    {
        HashMap<String, String> params = new HashMap<>();

        params.put("client_id",     provider.getClientId());
        params.put("nonce",         nonce                 );
        params.put("response_type", "code"                );
        params.put("redirect_uri",  redirectUri           );
        params.put("scope",         "openid email"        );
        params.put("state",         state                 );

        String query = OAuthUtils.unparseQuery(params);

        this.redirectUri = redirectUri;

        return "https://accounts.google.com/o/oauth2/v2/auth?" + query;
    }

    @Override
    public void readAuthenticationResponse(String responseUri)
    throws OAuthSessionException
    {
        URI uri;

        try {
            uri = new URI(responseUri);
        } catch (URISyntaxException e) {
            throw new OAuthSessionException("invalid response URI");
        }

        Map<String, String> params = OAuthUtils.parseQuery(uri.getRawQuery());

        String responseState = params.get("state");

        if (!state.equals(responseState))
            throw new OAuthSessionException("state mismatch");

        authenticationCode = params.get("code");
    }

    @Override
    public String getTokenRequestUrl()
    {
        return "https://oauth2.googleapis.com/token";
    }

    @Override
    public String getTokenRequestBody()
    {
        HashMap<String, String> params = new HashMap<>();

        params.put("code",          authenticationCode        );
        params.put("client_id",     provider.getClientId()    );
        params.put("client_secret", provider.getClientSecret());
        params.put("redirect_uri",  redirectUri               );
        params.put("grant_type",    "authorization_code"      );

        return OAuthUtils.unparseQuery(params);
    }

    @Override
    public void readTokenResponse(String responseBody)
    throws OAuthSessionException
    {
        GoogleOAuthTokenResponseJson response;

        try {
            response = mapper.readValue(responseBody, GoogleOAuthTokenResponseJson.class);
        } catch (JsonProcessingException e) {
            throw new OAuthSessionException("Invalid response: not JSON");
        }

        String[] jwtParts = response.id_token.split("\\.");

        if (jwtParts.length != 3)
            throw new OAuthSessionException("Invalid ID token: a JWT should have 3 period-separated parts");

        // Not validating signature on the JWT since it was received directly
        // over HTTPS.

        byte[] claims;

        try {
            claims = Base64.getUrlDecoder().decode(jwtParts[1]);
        } catch (IllegalArgumentException e) {
            throw new OAuthSessionException("Invalid ID token: JWT claims is not encoded as valid base64url");
        }

        GoogleOAuthIdTokenJson idToken;

        try {
            idToken = mapper.readValue(claims, GoogleOAuthIdTokenJson.class);
        } catch (IOException e) {
            throw new OAuthSessionException("Invalid ID token: JWT claims is not valid JSON", e);
        }

        if (!idToken.nonce.equals(nonce))
            throw new OAuthSessionException("nonce mismatch");

        subscriber = idToken.sub;
    }

    @Override
    public String getSubscriber()
    {
        return subscriber;
    }
}
