import * as Koa from "koa";
import { AppSessionState } from "./app-session";

export function csrfTokenAuth(): Koa.Middleware<AppSessionState> {
    return async (ctx, next) => {
        if (
            ctx.get("Authorization") !==
            `Bearer ${ctx.state.appSession.csrfToken}`
        ) {
            ctx.status = 403;
            ctx.body = {
                status: "error",
                message: "Invalid bearer token",
            };
            return;
        }
        await next();
    };
}
