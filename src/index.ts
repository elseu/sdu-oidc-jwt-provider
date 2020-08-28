import * as Koa from "koa";
import * as Router from "koa-router";
import * as logger from "koa-logger";
import * as json from "koa-json";
import * as dotenv from "dotenv";
import * as randomstring from "randomstring";
import ms = require("ms");

import { loadKeystore } from "./util/keystore";
import { jwtSession } from "./middleware/jwt-session";
import { isTruthy } from "./util/config";
import { appSession, AppSessionState } from "./middleware/app-session";
import { csrfTokenAuth } from "./middleware/csrf";
import { redirectChecker } from "./util/redirect-check";
import { loadOidcData } from "./util/oidc";

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
        (ctx: Koa.ParameterizedContext<AppSessionState>) => {
            ctx.body = "staaaay";
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
            ctx.cookies.set("oidc_state_" + state, state, {
                httpOnly: true,
                maxAge: ms("30m"),
            });
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
    app.use(appSession());
    app.use(router.middleware());

    const port = parseInt(process.env.PORT ?? "3000");

    console.groupEnd();

    app.listen(port, () => {
        console.log(`🚀 Listening on ${port}`);
    });
})();
