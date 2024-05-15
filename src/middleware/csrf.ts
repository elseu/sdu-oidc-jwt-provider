import * as Koa from "koa";
import { AppSessionState } from "./app-session";
import { verify } from "../util/jwt-promise";
import { JwtHeader, SigningKeyCallback } from "jsonwebtoken";
import * as jose from "node-jose";

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
            ctx.get("Authorization") ===
                `Bearer ${ctx.state.appSession.csrfToken}` ||
            ctx.query.token === ctx.state.appSession.csrfToken
        ) {
            await next();
            return;
        }

        const token = getTokenFromContext(ctx);

        if (token && options?.keystore) {
            const result = await verify(
                token,
                async (header: JwtHeader, callback: SigningKeyCallback) => {
                    if (!header.kid) {
                        callback("No kid in JWT header");
                        return;
                    }
                    const key = options.keystore.get(header.kid);
                    if (!key) {
                        callback("Unknown kid");
                        return;
                    }
                    callback(null, (await jose.JWK.asKey(key)).toPEM());
                }
            );

            // token is valid. continue
            if (result?.s) {
                await next();
                return;
            }
        }

        ctx.status = 403;
        ctx.body = {
            status: "error",
            message: "Invalid bearer token",
        };
    };
}
