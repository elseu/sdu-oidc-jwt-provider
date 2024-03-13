import * as Koa from "koa";
import * as jose from "node-jose";
import * as jwtPromise from "../util/jwt-promise";
import { JwtHeader, SigningKeyCallback, SignOptions } from "jsonwebtoken";
import ms = require("ms");
import {
    ClientSession,
    ClientSessionState,
    SessionData,
} from "./client-session";
import { isTruthy } from "../util/config";
import { applySameSiteFix } from "../util/samesite-cookiefix";

interface JWTSessionOptions {
    keystore: jose.JWK.KeyStore;
}

interface JWTSessionHandlerOptions extends JWTSessionOptions {
    tokenExpiresIn: string;
    algorithm: string;
}

interface JWTCookieData {
    headerPayload: string;
    signature: string;
}

class JWTSessionHandler implements ClientSession {
    keystore!: jose.JWK.KeyStore;
    tokenExpiresIn!: string;
    algorithm!: string;
    tokenData: SessionData | null;
    cookieData: JWTCookieData | null;
    cookieTokenPayload: SessionData | null;

    constructor(opts: JWTSessionHandlerOptions) {
        Object.assign(this, opts);
        this.cookieData = null;
        this.tokenData = null;
        this.cookieTokenPayload = null;
    }

    getData(): SessionData | null {
        return this.tokenData;
    }

    setData(data: SessionData | null) {
        this.tokenData = data;
        this.cookieData = null;
    }

    async setTokenCookieData(cookieData: JWTCookieData) {
        try {
            this.cookieData = cookieData;
            const token = `${cookieData.headerPayload}.${cookieData.signature}`;
            const result = await jwtPromise.verify(
                token,
                async (header: JwtHeader, callback: SigningKeyCallback) => {
                    if (!header.kid) {
                        callback("No kid in JWT header");
                        return;
                    }
                    const key = this.keystore.get(header.kid);
                    if (!key) {
                        callback("Unknown kid");
                        return;
                    }
                    callback(null, (await jose.JWK.asKey(key)).toPEM());
                }
            );
            if (result && !result.s) {
                throw new Error("Invalid session token");
            }
            this.cookieTokenPayload = result ?? null;
            this.tokenData = (result?.s as Record<string, unknown>) ?? null;
        } catch (_) {
            // Invalid token.
        }
    }

    async getTokenCookieData(): Promise<JWTCookieData | null> {
        if (this.cookieData !== null) {
            return this.cookieData;
        }
        if (this.tokenData !== null) {
            // Generate the cookie data.
            const signingKeys = this.keystore.all({ use: "sig" });
            if (signingKeys.length === 0) {
                throw new Error("No signing key available in keystore.");
            }
            const signingKey = signingKeys[0];
            const signingKeyPEM = (await jose.JWK.asKey(signingKey)).toPEM(
                true
            );

            const tokenPayload: SessionData = { s: this.tokenData };
            const signOptions: SignOptions = {
                keyid: signingKey.kid,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                algorithm: this.algorithm as any,
            };
            if (this.cookieTokenPayload?.exp) {
                // Maintain the same exp timestamp, so the session cannot be expanded past its planned expiration.
                tokenPayload.exp = this.cookieTokenPayload.exp;
            } else {
                signOptions.expiresIn = this.tokenExpiresIn;
            }

            const result = await jwtPromise.sign(
                tokenPayload,
                signingKeyPEM,
                signOptions
            );
            const parts = result.split(".");
            return {
                headerPayload: `${parts[0]}.${parts[1]}`,
                signature: parts[2],
            };
        }
        return null;
    }
}

export function jwtSession(
    opts: JWTSessionOptions
): Koa.Middleware<ClientSessionState> {
    const { keystore } = opts;

    // TODO: make configurable.
    const cookieName = process.env.SESSION_COOKIE_NAME ?? "sess";
    const cookieMaxAge = ms(process.env.SESSION_MAX_INACTIVE ?? "30m");
    const tokenExpiresIn = process.env.SESSION_MAX_AGE ?? "1d";
    const algorithm = process.env.SESSION_SIGNATURE_ALGORITHM ?? "RS256";
    const cookieSecure = isTruthy(process.env.COOKIES_SECURE ?? "true");
    const sessionExpireOnBrowserRestart = isTruthy(
        process.env.SESSION_EXPIRE_ON_BROWSER_RESTART ?? "true"
    );
    const sameSite = isTruthy(process.env.COOKIES_SECURE ?? "true")
        ? "none"
        : "lax";
    if (!cookieSecure) {
        console.warn(
            "⚠️  COOKIES_SECURE: sweet Jesus, Pooh! That's not honey! You're eating INSECURE COOKIES 🙀 Set this to true in production."
        );
    }
    const signatureCookieName = cookieName + "sig";

    return async (ctx, next) => {
        const sessionHandler = new JWTSessionHandler({
            keystore,
            tokenExpiresIn,
            algorithm,
        });
        ctx.state.clientSession = sessionHandler;

        // Load data from our cookies.
        const cookieHeaderPayload = ctx.cookies.get(cookieName);
        const cookieSignature = ctx.cookies.get(signatureCookieName);
        if (cookieHeaderPayload && cookieSignature) {
            await sessionHandler.setTokenCookieData({
                headerPayload: cookieHeaderPayload,
                signature: cookieSignature,
            });
        }

        await next();

        const defaultCookieOptions = applySameSiteFix(ctx, {
            secure: cookieSecure,
            httpOnly: true,
            sameSite,
        });

        // Store data back into cookies.
        const newCookieData = await sessionHandler.getTokenCookieData();
        if (newCookieData) {
            const { headerPayload, signature } = newCookieData;
            ctx.cookies.set(cookieName, headerPayload, {
                ...defaultCookieOptions,
                maxAge: cookieMaxAge,
            });
            ctx.cookies.set(signatureCookieName, signature, {
                ...defaultCookieOptions,
                ...(sessionExpireOnBrowserRestart
                    ? {}
                    : { maxAge: cookieMaxAge }),
            });
        } else if (cookieHeaderPayload && cookieSignature) {
            // Clear the cookies.
            ctx.cookies.set(cookieName, null, defaultCookieOptions);
            ctx.cookies.set(signatureCookieName, null, defaultCookieOptions);
        }
    };
}
