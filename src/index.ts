import * as Koa from "koa";
import * as Router from "koa-router";
import * as logger from "koa-logger";
import * as json from "koa-json";
import * as cors from "@koa/cors";
import * as dotenv from "dotenv";
import * as jsonwebtoken from "jsonwebtoken";
import * as randomstring from "randomstring";
import * as querystring from "querystring";
import * as Cookies from "cookies";
import ms = require("ms");

import { noCache } from "./middleware/no-cache";
import { loadKeystore } from "./util/keystore";
import { jwtSession } from "./middleware/jwt-session";
import { redisSession } from "./middleware/redis-session";
import { isTruthy } from "./util/config";
import { appSession, AppSessionState } from "./middleware/app-session";
import { csrfOrAccessTokenAuth } from "./middleware/csrf";
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
const statusRouter = new Router();

app.proxy = true;

(async () => {
  console.group("💥 Initializing...");

  const keystore = await loadKeystore();
  const checkRedirect = await redirectChecker();
  const oidcData = await loadOidcData();

  const defaultCookieOptions: Cookies.SetOption = {
    httpOnly: true,
    secure: isTruthy(process.env.COOKIES_SECURE ?? "true"),
    sameSite: isTruthy(process.env.COOKIES_SECURE ?? "true") ? "none" : "lax",
  };

  // Health check.
  statusRouter.get("/_health", (ctx) => {
    ctx.body = "OK";
  });

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
    csrfOrAccessTokenAuth(),
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
  router.get("/authorize", (ctx: Koa.ParameterizedContext<AppSessionState>) => {
    if (
      !ctx.query.redirect_uri ||
      typeof ctx.query.redirect_uri !== "string" ||
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
          scope: oidcData.scope,
          client_id: oidcData.credentials.clientId,
          state,
          redirect_uri: ctx.request.href.replace(/\/authorize.*$/, "/callback"),
        })
    );
  });

  // Receive code from the OIDC IdP and redirect back to our client.
  router.get(
    "/callback",
    async (ctx: Koa.ParameterizedContext<AppSessionState>) => {
      let tokens: OidcTokens | undefined;
      if (ctx.query.code && typeof ctx.query.code === "string") {
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
      const stateKey = ctx.query.state ?? ctx.cookies.get("oidc_state_last");
      if (!stateKey) {
        throw new Error("No state data.");
      }
      const stateCookieName = "oidc_state_" + stateKey;
      const stateCookie = ctx.cookies.get(stateCookieName);

      // Clear the state cookies.
      ctx.cookies.set("oidc_state_last", null, defaultCookieOptions);
      ctx.cookies.set(stateCookieName, null, defaultCookieOptions);

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
      if (appSession.accessToken) {
        const userInfo = await fetchUserInfo(appSession.accessToken, oidcData);
        if (userInfo) {
          appSession.userInfo = userInfo;
        }
      }
      const redirectParams: Record<string, string> = {
        token: appSession.csrfToken,
      };
      if (stateData.rs) {
        redirectParams.state = stateData.rs;
      }
      ctx.redirect(urlWithExtraParams(stateData.ru, redirectParams));
    }
  );

  // The application requests a logout.
  router.get("/logout", (ctx: Koa.ParameterizedContext<AppSessionState>) => {
    const { appSession } = ctx.state;
    const postLogoutRedirectUri =
      ctx.query.post_logout_redirect_uri &&
      typeof ctx.query.post_logout_redirect_uri === "string"
        ? ctx.query.post_logout_redirect_uri
        : null;
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
        ctx.cookies.set(cookieName, null, defaultCookieOptions);
        ctx.redirect(redirectUri);
      }
      ctx.body = "You are logged out";
    }
  );

  router.get(
    "/userinfo",
    csrfOrAccessTokenAuth({ keystore }),
    async (ctx: Koa.ParameterizedContext<AppSessionState>) => {
      ctx.body = ctx.state.appSession.userInfo ?? {};
    }
  );

  if (isTruthy(process.env.LOG_REQUESTS)) {
    app.use(logger());
  }
  app.use(
    cors({
      origin: (ctx) => {
        if (ctx.headers.origin && checkRedirect(ctx.headers.origin)) {
          return ctx.headers.origin;
        }
        return "";
      },
      credentials: true,
    })
  );
  app.use(json());

  const sessionStorage = process.env.SESSION_STORAGE ?? "jwt";
  switch (sessionStorage) {
    case "jwt":
      app.use(jwtSession({ keystore }));
      break;
    case "redis":
      app.use(redisSession());
      break;
    default:
      throw new Error(
        `Invalid value for SESSION_STORAGE: ${sessionStorage}. Expect jwt,redis`
      );
  }

  app.use(noCache());
  app.use(appSession({ keystore }));
  app.use(statusRouter.routes()).use(statusRouter.allowedMethods());
  app.use(router.routes()).use(router.allowedMethods());

  const port = parseInt(process.env.PORT ?? "3000");

  console.groupEnd();

  app.listen(port, () => {
    console.log(`🚀 Listening on ${port}`);
  });
})();

/**
 * Add extra query params to a URL, and handle cases like fragments an existing query string.
 * @param url
 * @param params
 */
function urlWithExtraParams(
  url: string,
  params: Record<string, string>
): string {
  const [urlWithoutHash, urlHash] = url.split("#", 2);
  if (urlHash) {
    return urlWithExtraParams(urlWithoutHash, params) + "#" + urlHash;
  }
  return (
    urlWithoutHash +
    (urlWithoutHash.indexOf("?") === -1 ? "?" : "&") +
    querystring.stringify(params)
  );
}
