import { BaseContext } from "koa";
import { SetOption } from "cookies";

/**
 * Safari on iOS 12 and some other really old browsers cannot handle SameSite=None. They only support SameSite without =... and
 * will interpret SameSite=None as just "SameSite", meaning SameSite=Strict. This is exactly the OPPOSITE of SameSite=None.
 * As a result, SameSite cookies will get lost on these browsers, causing errors on the frontend.
 * This fix will remove the SameSite annotation for cookies in those browsers. Since those browsers don't have the strict
 * standards for third-party cookies that modern browsers have, cookies without SameSite will work just fine there.
 * This code is based on a fix that has already been battle-tested in production with Sdu's oidc-mfa-proxy for a year or two.
 *
 * See: https://bugs.webkit.org/show_bug.cgi?id=198181
 */
export const applySameSiteFix = (
    ctx: BaseContext,
    cookieOptions: SetOption
): SetOption => {
    const modifiedOptions = { ...cookieOptions };
    const userAgent = ctx.header["user-agent"] || "";
    const browserSupportsSameSite = !userAgent.match(
        /((iPhone|iPad).*OS 12_|Chrome\/5|Chrome\/6|Safari.*OS X 10_14_|OS X 10_14_.*Safari|PostmanRuntime\/7)/
    );
    if (
        !browserSupportsSameSite &&
        modifiedOptions.sameSite &&
        modifiedOptions.sameSite !== "strict"
    ) {
        // The browser does not support SameSite=None or SameSite=Lax; remove the entire annotation.
        delete modifiedOptions.sameSite;
    }
    return modifiedOptions;
};
