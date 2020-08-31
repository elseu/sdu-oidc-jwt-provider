import * as Koa from "koa";
import * as Router from "koa-router";
import * as logger from "koa-logger";
import * as json from "koa-json";
import * as dotenv from "dotenv";
import * as randomstring from "randomstring";
import * as querystring from "querystring";
import ms = require("ms");

import { loadKeystore } from "./util/keystore";
import { jwtSession } from "./middleware/jwt-session";
import { isTruthy } from "./util/config";
import { appSession, AppSessionState } from "./middleware/app-session";
import { csrfTokenAuth } from "./middleware/csrf";
import { redirectChecker } from "./util/redirect-check";
import { loadOidcData, fetchTokens, OidcTokens } from "./util/oidc";

dotenv.config();

const app = new Koa();
const router = new Router();

(async () => {
    console.group("💥 Initializing...");

    const keystore = await loadKeystore();
    const checkRedirect = await redirectChecker();
    const oidcData = await loadOidcData();

    // JWKS endpoint.
    router.get("/.well-known/jwks.json", (ctx) => {
        ctx.body = keystore.toJSON(false);
    });

    // Partial OpenID discovery document.
    router.get("/.well-known/openid-configuration", (ctx) => {
        ctx.body = {
            jwks_uri: ctx.request.href.replace(
                /\/openid-configuration/,
                "/jwks.json"
            ),
        };
    });

    // Get a usable access token, *if* we have a session.
    router.get(
        "/token",
        csrfTokenAuth(),
        async (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            const { appSession, generateAppAccessToken } = ctx.state;
            let isAuthorized = false;
            if (ctx.headers["authorization"]) {
                const match = ctx.headers["authorization"].match(
                    /^Bearer\s+(.*)$/
                );
                if (match) {
                    isAuthorized = match[1] === appSession.csrfToken;
                }
            }
            if (!isAuthorized) {
                ctx.status = 403;
                ctx.body = { error: "Invalid token" };
                return;
            }
            ctx.body = {
                token: await generateAppAccessToken(),
            };
        }
    );

    // Authorize through the OIDC IdP.
    router.get(
        "/authorize",
        (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            if (
                !ctx.query.redirect_uri ||
                !checkRedirect(ctx.query.redirect_uri)
            ) {
                ctx.status = 400;
                ctx.body = "Invalid redirect_uri";
                return;
            }
            const state = randomstring.generate(32);
            const stateCookie = JSON.stringify({
                rs: ctx.query.state || null,
                ru: ctx.query.redirect_uri,
            });
            const cookieOptions = {
                httpOnly: true,
                maxAge: ms("30m"),
            };
            const queryParams = { ...ctx.query };
            delete queryParams.redirect_uri;

            ctx.cookies.set("oidc_state_last", state, cookieOptions);
            ctx.cookies.set("oidc_state_" + state, stateCookie, cookieOptions);
            ctx.redirect(
                oidcData.endpoints.authorization +
                    "?" +
                    querystring.stringify({
                        ...queryParams,
                        response_type: "code",
                        scope: oidcData.scope,
                        client_id: oidcData.credentials.clientId,
                        state,
                        redirect_uri: ctx.request.href.replace(
                            /\/authorize.*$/,
                            "/callback"
                        ),
                    })
            );
        }
    );

    // Receive code from the OIDC IdP and redirect back to our client.
    router.get(
        "/callback",
        async (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            let tokens: OidcTokens | undefined;
            if (ctx.query.code) {
                // Fetch tokens from the OIDC endpoint.
                try {
                    tokens = await fetchTokens(
                        ctx.query.code,
                        ctx.request.href.replace(/\?.*/, ""),
                        oidcData
                    );
                } catch (e) {
                    console.error(e);
                }
            }
            const stateKey =
                ctx.query.state ?? ctx.cookies.get("oidc_state_last");
            if (!stateKey) {
                throw new Error("No state data.");
            }
            const stateCookieName = "oidc_state_" + stateKey;
            const stateCookie = ctx.cookies.get(stateCookieName);

            // Clear the state cookies.
            ctx.cookies.set("oidc_state_last");
            ctx.cookies.set(stateCookieName);

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            let stateData: any;
            if (stateCookie) {
                try {
                    stateData = JSON.parse(stateCookie);
                } catch (e) {
                    console.error("Invalid state cookie", stateCookie);
                }
            }
            if (!stateData) {
                throw new Error("No state data.");
            }
            const { appSession } = ctx.state;
            appSession.accessToken = tokens?.accessToken;
            appSession.idToken = tokens?.idToken;
            const redirectParams: Record<string, string> = {
                token: appSession.csrfToken,
            };
            if (stateData.rs) {
                redirectParams.state = stateData.rs;
            }
            ctx.redirect(
                stateData.ru + "?" + querystring.stringify(redirectParams)
            );
        }
    );

    router.get("/logout", (ctx: Koa.ParameterizedContext<AppSessionState>) => {
        ctx.body = "staaaay";
    });

    // Health check.
    router.get("/_health", (ctx) => {
        ctx.body = "OK";
    });

    if (isTruthy(process.env.LOG_REQUESTS)) {
        app.use(logger());
    }
    app.use(json());
    app.use(jwtSession({ keystore }));
    app.use(appSession({ keystore }));
    app.use(router.middleware());

    const port = parseInt(process.env.PORT ?? "3000");

    console.groupEnd();

    app.listen(port, () => {
        console.log(`🚀 Listening on ${port}`);
    });
})();
