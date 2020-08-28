import { isTruthy } from "./config";
import * as randomstring from "randomstring";
import * as micromatch from "micromatch";
import * as url from "url";

type RedirectChecker = (uri: string) => boolean;

export async function redirectChecker(): Promise<RedirectChecker> {
    const hosts = (process.env.REDIRECT_ALLOW_HOSTS ?? "")
        .split(",")
        .filter((x) => x);
    if (hosts.length === 0) {
        throw new Error("REDIRECT_ALLOW_HOSTS: this is required.");
    }
    const allowInsecure = isTruthy(
        process.env.REDIRECT_ALLOW_INSECURE ?? "false"
    );
    if (allowInsecure) {
        console.warn(
            "⚠️  REDIRECT_ALLOW_INSECURE: allowing insecure redirects is DANGEROUS because your traffic may be intercepted."
        );
    }

    const randomHost =
        randomstring.generate(32) + "." + randomstring.generate(2);
    if (micromatch.any(randomHost, hosts)) {
        console.warn(
            "⚠️  REDIRECT_ALLOW_HOSTS: this is probably set too liberally; it looks like it can match anything."
        );
    }
    console.log("Allowed hosts:", hosts);

    return (uri: string): boolean => {
        let parsedUrl!: url.Url;
        try {
            parsedUrl = url.parse(uri);
        } catch (e) {
            // Don't allow invalid URLs.
            return false;
        }
        if (!allowInsecure && parsedUrl.protocol !== "https:") {
            // Only allow HTTPS when insecure redirects are not allowed (the default).
            return false;
        }
        if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
            // Only allow HTTP or HTTPS redirects.
            return false;
        }
        if (!parsedUrl.host || !micromatch.any(parsedUrl.host, hosts)) {
            // Host is not allowed.
            return false;
        }
        return true;
    };
}
