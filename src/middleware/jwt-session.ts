import * as Koa from "koa";
import * as jose from "node-jose";
import * as jwtPromise from "../util/jwt-promise";
import { JwtHeader, SigningKeyCallback, SignOptions } from "jsonwebtoken";
import ms = require("ms");
import { isTruthy } from "../util/config";

interface JWTSessionOptions {
    keystore: jose.JWK.KeyStore;
}

export interface JWTSessionState {
    jwtSession: JWTSession;
}

type JWTData = Record<string, unknown>;

interface JWTSession {
    getData(): JWTData | null;
    setData(data: JWTData | null): void;
}

interface JWTSessionHandlerOptions extends JWTSessionOptions {
    tokenExpiresIn: string;
    algorithm: string;
}

interface JWTCookieData {
    headerPayload: string;
    signature: string;
}

class JWTSessionHandler implements JWTSession {
    keystore!: jose.JWK.KeyStore;
    tokenExpiresIn!: string;
    algorithm!: string;
    tokenData: JWTData | null;
    cookieData: JWTCookieData | null;
    cookieTokenPayload: JWTData | null;

    constructor(opts: JWTSessionHandlerOptions) {
        Object.assign(this, opts);
        this.cookieData = null;
        this.tokenData = null;
        this.cookieTokenPayload = null;
    }

    getData(): JWTData | null {
        return this.tokenData;
    }

    setData(data: JWTData | null) {
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

            const tokenPayload: JWTData = { s: this.tokenData };
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
): Koa.Middleware<JWTSessionState> {
    const { keystore } = opts;

    // TODO: make configurable.
    const cookieName = process.env.SESSION_COOKIE_NAME ?? "sess";
    const cookieMaxAge = ms(process.env.SESSION_MAX_INACTIVE ?? "30m");
    const tokenExpiresIn = process.env.SESSION_MAX_AGE ?? "1d";
    const algorithm = process.env.SESSION_SIGNATURE_ALGORITHM ?? "RS256";
    const cookieSecure = isTruthy(process.env.SESSION_SECURE ?? "true");
    if (!cookieSecure) {
        console.warn(
            "⚠️  SESSION_SECURE: sweet Jesus, Pooh! That's not honey! You're eating INSECURE COOKIES 🙀 Set this to true in production."
        );
    }
    const signatureCookieName = cookieName + "sig";

    return async (ctx, next) => {
        const sessionHandler = new JWTSessionHandler({
            keystore,
            tokenExpiresIn,
            algorithm,
        });
        ctx.state.jwtSession = sessionHandler;

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

        // Store data back into cookies.
        const newCookieData = await sessionHandler.getTokenCookieData();
        if (newCookieData) {
            const { headerPayload, signature } = newCookieData;
            ctx.cookies.set(cookieName, headerPayload, {
                secure: cookieSecure,
                httpOnly: true,
                maxAge: cookieMaxAge,
            });
            ctx.cookies.set(signatureCookieName, signature, {
                secure: cookieSecure,
                httpOnly: true,
            });
        } else if (cookieHeaderPayload && cookieSignature) {
            // Clear the cookies.
            ctx.cookies.set(cookieName);
            ctx.cookies.set(signatureCookieName);
        }
    };
}
