// Copyright (c) 2024-2025 Julian Parkin
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

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Optional;
import java.util.Scanner;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.templ.handlebars.HandlebarsTemplateEngine;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;

import ca.uwaterloo.fivegakabyoi.shared.SqnGeneratorProfile1;
import ca.uwaterloo.fivegakabyoi.shared.Suci;
import ca.uwaterloo.fivegakabyoi.shared.SuciEncryptionProfile;
import ca.uwaterloo.fivegakabyoi.shared.SuciEncryptionProfileA;
import ca.uwaterloo.fivegakabyoi.shared.X25519Loader;
import ca.uwaterloo.fivegakabyoi.shared.X25519LoadingException;

import ca.uwaterloo.fivegakabyoi.ueemulator.nas.NasEndpoint;

public class UeEmulator extends AbstractVerticle
{
    // HN/SN IDs: not modelling roaming, so HN = SN
    private static final String SN_MCC = "302";
    private static final String SN_MNC = "000";
    private static final String HN_MCC = "302";
    private static final String HN_MNC = "000";

    private static final Logger log = LogManager.getLogger();

    private Usim                     usim;
    private UeNasThread              ue;
    private SnNasThread              sn;
    private HttpServer               httpServer;
    private HandlebarsTemplateEngine engine;

    private String                   userId;
    private String                   authServer;
    private String                   authUrl;

    @Override
    public void start(Promise<Void> startPromise)
    {
        log.trace("start()");

        log.info("Starting UE Emulation HTTP server");

        log.info("Loading USIM");

        try {
            usim = loadUsim();
        } catch (UsimLoadingException e) {
            log.fatal("Unable to load USIM", e);

            startPromise.fail(e);
            return;
        }

        log.info("Building HN");

        HnAusfUdm hn;

        try {
            hn = buildHn(usim);
        } catch (OAuthProviderException e) {
            log.fatal("Unable to instantiate OAuthProvider", e);

            startPromise.fail(e);
            return;
        } catch (X25519LoadingException e) {
            log.fatal("Unable to load HN private key", e);

            startPromise.fail(e);
            return;
        }

        log.info("Starting UE and SN NAS threads");

        ue = new UeNasThread(usim);
        sn = new SnNasThread(SN_MCC, SN_MNC, hn);

        NasEndpoint snNas = sn.connect(ue.getNasEndpoint());

        ue.connect(snNas, sn.getSnName());

        ue.start();
        sn.start();

        engine = HandlebarsTemplateEngine.create(vertx);

        log.info("Creating HTTP server");

        Router router = Router.router(vertx);

        log.debug("Adding HTTP routes");

        addRoutes(router);

        httpServer = vertx.createHttpServer();

        httpServer.requestHandler(router)
            .listen(8080, res -> {
                if (res.succeeded()) {
                    log.info("HTTP server started successfully");

                    startPromise.complete();
                } else {
                    log.fatal("Unable to start HTTP server", res.cause());

                    startPromise.fail(res.cause());
                }
            });
    }

    @Override
    public void stop(Promise<Void> stopPromise)
    {
        log.trace("stop()");

        log.info("Stopping UE Emulation HTTP server");

        log.info("Stopping UE and SN NAS threads");

        ue.exit();
        sn.exit();

        log.info("Closing HTTP server");

        httpServer.close(res -> {
                if (res.succeeded()) {
                    log.info("HTTP server closed successfully");

                    stopPromise.complete();
                } else {
                    log.fatal("Failed to closed HTTP server", res.cause());

                    stopPromise.fail(res.cause());
                }
            });
    }

    private void addRoutes(Router router)
    {
        log.trace("addRoutes()");

        router.route(HttpMethod.GET, "/")
            .handler(ctx -> ctx.redirect("index.html"));

        router.route(HttpMethod.GET, "/index.html")
            .handler(ctx -> ctx.response()
                .sendFile("webroot/index.html")
                .onFailure(res -> ctx.next())
            );

        router.route(HttpMethod.GET, "/authenticate-confirm.html")
            .handler(ctx -> {
                HashMap<String, Object> templateContext = new HashMap<>();

                templateContext.put("AuthenticationServer", authServer);

                engine.render(templateContext, "webroot/authenticate-confirm.hbs")
                    .onSuccess(buffer -> {
                        ctx.response()
                            .putHeader("Content-Type", "text/html")
                            .end(buffer);
                    })
                    .onFailure(res -> ctx.next());
            });

        router.route(HttpMethod.GET, "/authenticate-complete.html")
            .handler(ctx -> ctx.response()
                .sendFile("webroot/authenticate-complete.html")
                .onFailure(res -> ctx.next())
            );

        router.route(HttpMethod.GET, "/css/:filename.css")
            .handler(ctx -> ctx.response()
                .sendFile("webroot/css/" + ctx.pathParam("filename") + ".css")
                .onFailure(res -> ctx.next())
            );

        router.route(HttpMethod.GET, "/js/:filename.js")
            .handler(ctx -> ctx.response()
                .sendFile("webroot/js/" + ctx.pathParam("filename") + ".js")
                .onFailure(res -> ctx.next())
            );

        router.route(HttpMethod.POST, "/authenticate")
            .handler(BodyHandler.create())
            .handler(ctx -> {
                userId = ctx.request().getFormAttribute("userid");

                log.debug("Got /authenticate with userid={}", userId);

                try {
                    ue.registrationRequest(userId, url -> {
                        try {
                            authUrl    = url;
                            authServer = getHostFromUrl(url);

                            ctx.redirect("/authenticate-confirm.html");
                        } catch (URISyntaxException e) {
                            ctx.response().setStatusCode(400).end();
                        }
                    });
                } catch (UeNasException e) {
                    ctx.response().setStatusCode(400).end();
                }
            });

        router.route(HttpMethod.GET, "/authenticate-redirect")
            .handler(ctx -> ctx.redirect(authUrl));

        router.route(HttpMethod.GET, "/oauth2-callback")
            .handler(ctx -> {
                ue.oauthAuthorizationResponse(ctx.request().absoluteURI(), () -> {
                    ctx.redirect("/authenticate-complete.html");
                });
            });
    }

    private static String getHostFromUrl(String url)
    throws URISyntaxException
    {
        URI uri = new URI(url);

        log.trace("getHostFromUrl({}) = {}", url, uri.getHost());

        return uri.getHost();
    }

    private static HnAusfUdm buildHn(Usim usim)
    throws OAuthProviderException, X25519LoadingException
    {
        log.trace("buildHn()");

        ArrayList<Usim> subscribers = new ArrayList<>();

        subscribers.add(usim);

        ArrayList<OAuthProvider> providers = new ArrayList<>();

        providers.add(buildGoogleOAuthProvider());

        InputStream                pem          = UeEmulator.class.getResourceAsStream("/hn_private_key.pem");
        X25519PrivateKeyParameters hnPrivateKey = X25519Loader.loadPrivateKey(pem);
        SuciEncryptionProfileA     suciDec      = new SuciEncryptionProfileA(null, hnPrivateKey, null, new SecureRandom());

        return new HnAusfUdm(
            HN_MCC,
            HN_MNC,
            subscribers,
            providers,
            "http://127.0.0.1:8080/oauth2-callback",
            new Suci.EncryptionProfileMap() {
                @Override
                public Optional<SuciEncryptionProfile> getEncryptionProfile(
                    String schemeId,
                    String hnPubkeyId
                )
                {
                    if (schemeId.equals("1") && hnPubkeyId.equals(usim.getHnPublicKeyId()))
                        return Optional.of(suciDec);
                    else
                        return Optional.empty();
                }
        });
    }

    private static OAuthProvider buildGoogleOAuthProvider()
    throws OAuthProviderException
    {
        log.trace("buildGoogleOAuthProvider()");

        String clientId     = System.getenv("GOOGLE_OAUTH2_CLIENT_ID");
        String clientSecret = System.getenv("GOOGLE_OAUTH2_CLIENT_SECRET");

        if (clientId == null)
            throw new OAuthProviderException("Missing environment variable GOOGLE_OAUTH2_CLIENT_ID");

        if (clientSecret == null)
            throw new OAuthProviderException("Missing environment variable GOOGLE_OAUTH2_CLIENT_ID");

        return new GoogleOAuthProvider(clientId, clientSecret);
    }

    private static Usim loadUsim()
    throws UsimLoadingException
    {
        log.trace("loadUsim()");

        InputStream s = UeEmulator.class.getResourceAsStream("/usim.json");

        // Read entire file into a string by using \A (beginning of input) as
        // delimiter, which never matches.
        String json = new Scanner(s, "UTF-8")
            .useDelimiter("\\A")
            .next();

        Usim usim = Usim.fromJson(json);

        SqnGeneratorProfile1 sqnGenerator = new SqnGeneratorProfile1(
            new SqnGeneratorClock(),
            0
        );

        // We aren't modelling a USIM with persistent storage, so initialize
        // the SQN to a value based on the current time.
        usim.setSqn(sqnGenerator.getInitialSqn());

        return usim;
    }
}
