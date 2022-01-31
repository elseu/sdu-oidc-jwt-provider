import * as Koa from "koa";
import * as randomstring from "randomstring";
import { createClient, RedisClient } from "redis";
import ms = require("ms");
import { promisify } from "util";
import {
    ClientSession,
    ClientSessionState,
    SessionData,
} from "./client-session";
import { isTruthy } from "../util/config";
import { applySameSiteFix } from "../util/samesite-cookiefix";

interface RedisSessionHandlerOptions {
    client: RedisClient;
    sessionExpiresIn: string;
}

interface RedisCookieData {
    payload: string;
    signature: string;
}

class RedisSessionHandler implements ClientSession {
    client!: RedisClient;
    sessionExpiresIn!: string;
    sessionData: SessionData | null;
    cookieData: RedisCookieData | null;

    constructor(opts: RedisSessionHandlerOptions) {
        Object.assign(this, opts);
        this.cookieData = null;
        this.sessionData = null;
    }

    getData(): SessionData | null {
        return this.sessionData;
    }

    setData(data: SessionData | null) {
        this.sessionData = data;
    }

    async setTokenCookieData(cookieData: RedisCookieData) {
        this.cookieData = cookieData;
    }

    async getTokenCookieData(): Promise<RedisCookieData | null> {
        return this.cookieData;
    }

    async loadData() {
        const key = this.redisKey();
        if (!key) {
            return;
        }
        const data = await promisify(this.client.get).bind(this.client)(key);
        if (data) {
            try {
                this.sessionData = JSON.parse(data);
            } catch (e) {
                console.error(`Invalid session data: ${data}`);
            }
        }
    }

    async storeData() {
        const key = this.redisKey();
        if (key) {
            // We have a Redis key from the cookie.
            if (this.sessionData) {
                // Store session data.
                await promisify(this.client.set).bind(this.client)(
                    key,
                    JSON.stringify(this.sessionData)
                );
                // Expire the data when the session expires.
                await promisify(this.client.expire).bind(this.client)(
                    key,
                    Math.ceil(ms(this.sessionExpiresIn) / 1000)
                );
            } else {
                // No session data; delete.
                await promisify<string, number>(this.client.del).bind(
                    this.client
                )(key);
            }
        } else {
            // No key.
            if (this.sessionData) {
                // We have data to store, so first generate a key, then store.
                this.cookieData = {
                    payload: randomstring.generate(32),
                    signature: randomstring.generate(32),
                };
                await this.storeData();
            }
        }
    }

    redisKey(): string | null {
        return this.cookieData
            ? `${this.cookieData.payload}.${this.cookieData.signature}`
            : null;
    }
}

export function redisSession(): Koa.Middleware<ClientSessionState> {
    const cookieName = process.env.SESSION_COOKIE_NAME ?? "sess";
    const cookieMaxAge = ms(process.env.SESSION_MAX_INACTIVE ?? "30m");
    const sessionExpiresIn = process.env.SESSION_MAX_AGE ?? "1d";
    const cookieSecure = isTruthy(process.env.COOKIES_SECURE ?? "true");
    const sessionExpireOnBrowserRestart = isTruthy(
        process.env.SESSION_EXPIRE_ON_BROWSER_RESTART ?? "true"
    );
    const sameSite = isTruthy(process.env.COOKIES_SECURE ?? "true")
        ? "none"
        : "lax";

    const redisUrl = process.env.REDIS_URL ?? "redis://localhost";
    console.log(`Redis URL: ${redisUrl}`);

    if (!cookieSecure) {
        console.warn(
            "⚠️  COOKIES_SECURE: sweet Jesus, Pooh! That's not honey! You're eating INSECURE COOKIES 🙀 Set this to true in production."
        );
    }
    const signatureCookieName = cookieName + "sig";

    const client = createClient({
        url: redisUrl,
    });

    return async (ctx, next) => {
        const sessionHandler = new RedisSessionHandler({
            client,
            sessionExpiresIn,
        });
        ctx.state.clientSession = sessionHandler;

        // Load data from our cookies.
        const cookiePayload = ctx.cookies.get(cookieName);
        const cookieSignature = ctx.cookies.get(signatureCookieName);
        if (cookiePayload && cookieSignature) {
            await sessionHandler.setTokenCookieData({
                payload: cookiePayload,
                signature: cookieSignature,
            });
        }

        await sessionHandler.loadData();
        await next();
        await sessionHandler.storeData();

        const defaultCookieOptions = applySameSiteFix(ctx, {
            secure: cookieSecure,
            httpOnly: true,
            sameSite,
        });

        // Store data back into cookies.
        const newCookieData = await sessionHandler.getTokenCookieData();
        if (newCookieData) {
            const { payload, signature } = newCookieData;
            ctx.cookies.set(cookieName, payload, {
                ...defaultCookieOptions,
                maxAge: cookieMaxAge,
            });
            ctx.cookies.set(signatureCookieName, signature, {
                ...defaultCookieOptions,
                ...(sessionExpireOnBrowserRestart
                    ? {}
                    : { maxAge: cookieMaxAge }),
            });
        } else if (cookiePayload && cookieSignature) {
            // Clear the cookies.
            ctx.cookies.set(cookieName, null, defaultCookieOptions);
            ctx.cookies.set(signatureCookieName, null, defaultCookieOptions);
        }
    };
}
