import * as Koa from "koa";
import * as jose from "node-jose";
import { AppSessionState } from "./app-session";

function getTokenFromContext(ctx: Koa.DefaultContext): string | null {
  const authHeader = ctx.headers.authorization;
  let token: null | string = null;
  if (authHeader) {
    const match = authHeader.match(/^Bearer[ ]+(.*)$/);
    if (match) {
      token = match[1];
    }
  }
  return token;
}

interface CsrfTokenAuthOptions {
  keystore: jose.JWK.KeyStore;
}

export function csrfOrAccessTokenAuth(
  options?: CsrfTokenAuthOptions
): Koa.Middleware<AppSessionState> {
  return async (ctx, next) => {
    if (
      ctx.get("Authorization") === `Bearer ${ctx.state.appSession.csrfToken}` ||
      ctx.query.token === ctx.state.appSession.csrfToken
    ) {
      await next();
      return;
    }

    const token = getTokenFromContext(ctx);

    if (token && options?.keystore) {
      try {
        await jose.JWS.createVerify(options.keystore).verify(token);

        await next();
        return;
      } catch (err) {
        ctx.status = 403;
        ctx.body = {
          status: "error",
          message: "Invalid bearer token",
        };
      }
    }

    ctx.status = 403;
    ctx.body = {
      status: "error",
      message: "Invalid bearer token",
    };
  };
}
