import * as Koa from "koa";
import * as jose from "node-jose";
import * as randomstring from "randomstring";
import { JWTSessionState } from "./jwt-session";
import { sign } from "../util/jwt-promise";

export interface AppSession extends Record<string, unknown> {
    csrfToken: string;
    idToken?: string;
    accessTokenData?: Record<string, unknown>;
    userInfo?: Record<string, unknown>;
}

export interface AppSessionState {
    appSession: AppSession;
    generateAppAccessToken(): Promise<string | null>;
    clearAppSession(): void;
}

export function appSession(opts: {
    keystore: jose.JWK.KeyStore;
}): Koa.Middleware<JWTSessionState & AppSessionState> {
    const { keystore } = opts;
    const accessTokenExpiresIn = process.env.ACCESS_TOKEN_EXPIRES_IN ?? "5m";
    const accessTokenAlgorithm = process.env.ACCESS_TOKEN_ALGORITHM ?? "RS256";

    const signingKeys = keystore.all({ use: "sig" });
    if (signingKeys.length === 0) {
        throw new Error("No signing key available in keystore.");
    }
    const signingKey = signingKeys[0];
    const signingKeyPEM = jose.JWK.asKey(signingKey).then((key) =>
        key.toPEM(true)
    );

    return async (ctx, next) => {
        ctx.state.appSession = sessionDataFromJWT(
            ctx.state.jwtSession.getData()
        );
        ctx.state.generateAppAccessToken = async () => {
            const issuer =
                process.env.ACCESS_TOKEN_ISSUER ??
                ctx.request.href.replace(/^(https?:\/\/[^/]+).*$/, "$1/");
            const audience =
                process.env.ACCESS_TOKEN_AUDIENCE ?? issuer + "resources";

            const { accessTokenData } = ctx.state.appSession;
            if (!accessTokenData) {
                return null;
            }
            const tokenData: Record<string, unknown> & {
                orig: Record<string, unknown>;
            } = {
                iss: issuer,
                aud: audience,
                orig: {},
            };
            const skipKeys = ["iat", "exp", "nbf"];
            const hideKeys = ["client_id"];
            Object.entries(accessTokenData).forEach(([k, v]) => {
                if (hideKeys.includes(k)) {
                    // Do nothing.
                } else if (!(k in tokenData) && !skipKeys.includes(k)) {
                    tokenData[k] = v;
                } else {
                    tokenData.orig[k] = v;
                }
            });

            const signingKeyData = await signingKeyPEM;
            return await sign(tokenData, signingKeyData, {
                expiresIn: accessTokenExpiresIn,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                algorithm: accessTokenAlgorithm as any,
            });
        };
        ctx.state.clearAppSession = () => {
            delete ctx.state.appSession.accessTokenData;
            delete ctx.state.appSession.csrfToken;
            delete ctx.state.appSession.idToken;
            delete ctx.state.appSession.userInfo;
        };
        await next();
        ctx.state.jwtSession.setData(ctx.state.appSession);
    };
}

function sessionDataFromJWT(data: Record<string, unknown> | null): AppSession {
    const output: Partial<AppSession> = data ?? {};
    if (!output.csrfToken) {
        output.csrfToken = randomstring.generate(16);
    }
    return output as AppSession;
}
