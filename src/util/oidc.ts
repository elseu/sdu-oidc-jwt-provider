import fetch from "node-fetch";
import * as querystring from "querystring";
import * as jwksRsa from "jwks-rsa";

export interface OidcEndpoints {
    authorization: string;
    token: string;
    jwks?: string;
    userinfo?: string;
    endSession?: string;
}

export interface OidcClientCredentials {
    clientId: string;
    clientSecret: string;
}

export interface OidcData {
    endpoints: OidcEndpoints;
    credentials: OidcClientCredentials;
    scope: string;
    jwksClient?: jwksRsa.JwksClient;
}

export interface OidcTokens {
    accessToken: string;
    idToken: string;
}

export async function loadOidcData(): Promise<OidcData> {
    const endpoints = await innerLoadOidcEndpoints();
    console.group("OIDC endpoints:");
    Object.entries(endpoints).forEach(([k, v]) => {
        console.log(`${k}:`, v);
    });
    console.groupEnd();
    if (!process.env.OIDC_CLIENT_ID) {
        throw new Error("Need OIDC_CLIENT_ID");
    }
    if (!process.env.OIDC_CLIENT_SECRET) {
        throw new Error("Need OIDC_CLIENT_SECRET");
    }
    const scope = process.env.OIDC_SCOPE ?? "openid profile";
    const output: OidcData = {
        endpoints,
        scope,
        credentials: {
            clientId: process.env.OIDC_CLIENT_ID,
            clientSecret: process.env.OIDC_CLIENT_SECRET,
        },
    };
    if (endpoints.jwks) {
        output.jwksClient = jwksRsa({
            jwksUri: endpoints.jwks,
            rateLimit: true,
            strictSsl: true,
            jwksRequestsPerMinute: 1,
        });
    }
    return output;
}

export async function fetchTokens(
    code: string,
    redirectUri: string,
    oidcData: OidcData
): Promise<OidcTokens> {
    const { clientId, clientSecret } = oidcData.credentials;
    const response = await fetch(oidcData.endpoints.token, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization:
                "Basic " +
                Buffer.from(clientId + ":" + clientSecret, "utf-8").toString(
                    "base64"
                ),
        },
        body: querystring.stringify({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
        }),
    });
    const tokens = await response.json();
    if (!tokens || !tokens.access_token || !tokens.id_token) {
        console.error("Error while fetching tokens", tokens);
        throw new Error("No tokens received.");
    }
    return {
        accessToken: tokens.access_token,
        idToken: tokens.id_token,
    };
}

export async function fetchUserInfo(
    accessToken: string,
    oidcData: OidcData
): Promise<Record<string, unknown> | null> {
    if (!oidcData.endpoints.userinfo) {
        return null;
    }
    const response = await fetch(oidcData.endpoints.userinfo, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    return (await response.json()) ?? null;
}

async function innerLoadOidcEndpoints(): Promise<OidcEndpoints> {
    const output: Partial<OidcEndpoints> = {};
    if (process.env.OIDC_AUTHORIZATION_ENDPOINT) {
        output.authorization = process.env.OIDC_AUTHORIZATION_ENDPOINT;
    }
    if (process.env.OIDC_TOKEN_ENDPOINT) {
        output.token = process.env.OIDC_TOKEN_ENDPOINT;
    }
    if (process.env.OIDC_JWKS_ENDPOINT) {
        output.jwks = process.env.OIDC_JWKS_ENDPOINT;
    }
    if (process.env.OIDC_USERINFO_ENDPOINT) {
        output.userinfo = process.env.OIDC_USERINFO_ENDPOINT;
    }
    if (process.env.OIDC_ENDSESSION_ENDPOINT) {
        output.endSession = process.env.OIDC_ENDSESSION_ENDPOINT;
    }
    if (process.env.OIDC_DISCOVERY_URL) {
        // Perform discovery.
        const discoveryData = await (
            await fetch(process.env.OIDC_DISCOVERY_URL)
        ).json();
        output.authorization = discoveryData.authorization_endpoint;
        output.token = discoveryData.token_endpoint;
        if (discoveryData.jwks_uri) {
            output.jwks = discoveryData.jwks_uri;
        }
        if (discoveryData.userinfo_endpoint) {
            output.userinfo = discoveryData.userinfo_endpoint;
        }
        if (discoveryData.end_session_endpoint) {
            output.endSession = discoveryData.end_session_endpoint;
        }
    }
    return output as OidcEndpoints;
}
