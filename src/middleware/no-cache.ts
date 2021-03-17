import * as Koa from "koa";

export function noCache(): Koa.Middleware {
    return async (ctx, next) => {
        await next();
        ctx.set("Cache-Control", "no-store, no-cache, must-revalidate");
        ctx.set("Pragma", "no-cache");
        ctx.set("Expires", "0");
    };
}
