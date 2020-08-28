import fetch from "node-fetch";
import * as jwksRsa from "jwks-rsa";

export interface OidcEndpoints {
    authorization: string;
    token: string;
    jwks?: string;
    userinfo?: string;
    endSession?: string;
}

export interface OidcData {
    endpoints: OidcEndpoints;
    jwksClient?: jwksRsa.JwksClient;
}

export async function loadOidcData(): Promise<OidcData> {
    const endpoints = await innerLoadOidcEndpoints();
    console.group("OIDC endpoints:");
    Object.entries(endpoints).forEach(([k, v]) => {
        console.log(`${k}:`, v);
    });
    console.groupEnd();
    const output: OidcData = { endpoints };
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
