import * as Koa from "koa";
import * as randomstring from "randomstring";
import { JWTSessionState } from "./jwt-session";

export interface AppSession extends Record<string, unknown> {
    csrfToken: string;
    idToken?: string;
    accessToken?: string;
}

export interface AppSessionState {
    appSession: AppSession;
}

export function appSession(): Koa.Middleware<
    JWTSessionState & AppSessionState
> {
    return async (ctx, next) => {
        ctx.state.appSession = sessionDataFromJWT(
            ctx.state.jwtSession.getData()
        );
        await next();
        ctx.state.jwtSession.setData(ctx.state.appSession);
    };
}

function sessionDataFromJWT(data: Record<string, unknown> | null): AppSession {
    const output: Partial<AppSession> = data ?? { haveSession: false };
    if (!output.csrfToken) {
        output.csrfToken = randomstring.generate(16);
    }
    return output as AppSession;
}
