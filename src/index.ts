import * as Koa from "koa";
import * as Router from "koa-router";
import * as logger from "koa-logger";
import * as json from "koa-json";
import * as cors from "@koa/cors";
import * as dotenv from "dotenv";
import * as jsonwebtoken from "jsonwebtoken";
import * as randomstring from "randomstring";
import * as querystring from "querystring";
import ms = require("ms");

import { loadKeystore } from "./util/keystore";
import { jwtSession } from "./middleware/jwt-session";
import { isTruthy } from "./util/config";
import { appSession, AppSessionState } from "./middleware/app-session";
import { csrfTokenAuth } from "./middleware/csrf";
import { redirectChecker } from "./util/redirect-check";
import {
    loadOidcData,
    fetchTokens,
    fetchUserInfo,
    OidcTokens,
} from "./util/oidc";

dotenv.config();

const app = new Koa();
const router = new Router();

(async () => {
    console.group("💥 Initializing...");

    const keystore = await loadKeystore();
    const checkRedirect = await redirectChecker();
    const oidcData = await loadOidcData();

    const defaultCookieOptions = {
        httpOnly: true,
        secure: isTruthy(process.env.COOKIES_SECURE ?? "true"),
    };

    // JWKS endpoint.
    router.get("/.well-known/jwks.json", (ctx) => {
        ctx.body = keystore.toJSON(false);
    });

    // Partial OpenID discovery document.
    router.get("/.well-known/openid-configuration", (ctx) => {
        const baseUrl = ctx.request.href.replace(
            /\/.well-known\/openid-configuration.*$/,
            ""
        );
        const issuer = process.env.ISSUER ?? baseUrl + "/";
        ctx.body = {
            issuer,
            jwks_uri: `${baseUrl}/.well-known/jwks.json`,
            token_endpoint: `${baseUrl}/token`,
            authorization_endpoint: `${baseUrl}/authorize`,
            end_session_endpoint: `${baseUrl}/logout`,
            userinfo_endpoint: `${baseUrl}/userinfo`,
        };
    });

    // Get a usable access token, *if* we have a session.
    router.get(
        "/token",
        csrfTokenAuth(),
        async (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            const { generateAppAccessToken } = ctx.state;
            const token = await generateAppAccessToken();
            const claims = token ? jsonwebtoken.decode(token) : null;
            ctx.body = {
                token,
                claims,
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
                ...defaultCookieOptions,
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
                        scope: ctx.query.scope ?? "openid profile",
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

    // The application requests a logout.
    router.get("/logout", (ctx: Koa.ParameterizedContext<AppSessionState>) => {
        const { appSession } = ctx.state;
        const postLogoutRedirectUri = ctx.query.post_logout_redirect_uri;
        if (postLogoutRedirectUri && !checkRedirect(postLogoutRedirectUri)) {
            ctx.status = 403;
            ctx.body = "Invalid post_logout_redirect_uri";
            return;
        }
        if (oidcData.endpoints.endSession && appSession.idToken) {
            // First log out of the external IdP.
            const cookieOptions = {
                ...defaultCookieOptions,
                maxAge: ms("10m"),
            };
            ctx.cookies.set(
                "oidc_logout_redirect_uri",
                postLogoutRedirectUri ?? "",
                cookieOptions
            );
            ctx.redirect(
                oidcData.endpoints.endSession +
                    "?" +
                    querystring.stringify({
                        id_token_hint: appSession.idToken,
                        post_logout_redirect_uri: ctx.request.href.replace(
                            /\/logout.*$/,
                            "/logged-out"
                        ),
                    })
            );
            return;
        }

        // Log out right now.
        ctx.state.clearAppSession();
        if (postLogoutRedirectUri) {
            ctx.redirect(postLogoutRedirectUri);
            return;
        }
        ctx.body = "You are logged out";
    });

    // The OIDC IdP wants us to log out.
    router.get(
        "/front-channel-logout",
        (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            // Clear our session.
            ctx.state.clearAppSession();
            ctx.body = "";
        }
    );

    // The OIDC IdP is done logging us out.
    router.get(
        "/logged-out",
        (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            // Clear our session.
            ctx.state.clearAppSession();

            const cookieName = "oidc_logout_redirect_uri";
            const redirectUri = ctx.cookies.get(cookieName);

            if (redirectUri) {
                ctx.cookies.set(cookieName);
                ctx.redirect(redirectUri);
            }
            ctx.body = "You are logged out";
        }
    );

    router.get(
        "/userinfo",
        csrfTokenAuth(),
        async (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            const { accessToken } = ctx.state.appSession;
            if (!accessToken) {
                ctx.body = {};
                return;
            }
            const userInfo = await fetchUserInfo(accessToken, oidcData);
            ctx.body = userInfo;
        }
    );

    // Health check.
    router.get("/_health", (ctx) => {
        ctx.body = "OK";
    });

    if (isTruthy(process.env.LOG_REQUESTS)) {
        app.use(logger());
    }
    app.use(
        cors({
            origin: (ctx) => {
                if (ctx.headers.origin && checkRedirect(ctx.headers.origin)) {
                    return ctx.headers.origin;
                }
            },
            credentials: true,
        })
    );
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
