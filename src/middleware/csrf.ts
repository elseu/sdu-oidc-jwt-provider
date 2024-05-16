import * as Koa from "koa";
import { AppSessionState } from "./app-session";

export function csrfTokenAuth(): Koa.Middleware<AppSessionState> {
  return async (ctx, next) => {
    if (
      ctx.get("Authorization") === `Bearer ${ctx.state.appSession.csrfToken}` ||
      ctx.query.token === ctx.state.appSession.csrfToken
    ) {
      await next();
      return;
    }

    ctx.status = 403;
    ctx.body = {
      status: "error",
      message: "Invalid bearer token",
    };
  };
}
