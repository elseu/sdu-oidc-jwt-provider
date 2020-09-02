/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable no-undef */
(window || global).oidcJwtProvider = (function () {
    var app = __CONTEXT;

    var csrfTokenStorageKey = "oidc_jwt_provider_token";
    var csrfToken = sessionStorage.getItem(csrfTokenStorageKey) || null;

    var accessTokenCache;
    var userInfoCache;

    function promise(execute) {
        var handlers = [];
        var result = null;
        function resolve(r) {
            result = r;
            handlers = handlers.map(function (f) {
                f();
            });
        }
        function resolveError(error) {
            resolve([true, error]);
        }
        function resolveValue(value) {
            resolve([false, value]);
        }
        function thrower(error) {
            throw error;
        }
        function then(onResolved, onRejected) {
            return promise(function (resolve, reject) {
                function resolveWith(f) {
                    return function (value) {
                        try {
                            resolve(f(value));
                        } catch (error) {
                            reject(error);
                        }
                    };
                }
                function handle() {
                    setTimeout(function () {
                        result[0]
                            ? resolveWith(onRejected || thrower)(result[1])
                            : resolveWith(onResolved)(result[1]);
                    }, 0);
                }
                result ? handle() : handlers.push(handle);
            });
        }
        try {
            execute(function (r) {
                r && typeof r.then === "function"
                    ? r.then(resolveValue, resolveError)
                    : resolveValue(r);
            }, resolveError);
        } catch (error) {
            resolveError(error);
        }
        return { then: then };
    }

    function xhrFetch(url, options) {
        return promise(function (resolve, reject) {
            var req = new XMLHttpRequest();
            req.addEventListener("load", function () {
                resolve(this);
            });
            req.addEventListener("error", function (error) {
                reject(error);
            });
            req.open(options && options.method ? options.method : "GET", url);
            if (options && options.headers) {
                for (var k in options.headers) {
                    req.setRequestHeader(k, options.headers[k]);
                }
            }
            if (options.credentials === "include") {
                req.withCredentials = true;
            }
            if (options && options.body) {
                req.send(options.body);
            } else {
                req.send();
            }
        });
    }

    function xhrFetchJsonWithAuth(url) {
        return xhrFetch(url, {
            headers: {
                Authorization: "Bearer " + csrfToken,
            },
            credentials: "include",
        }).then(function (response) {
            return JSON.parse(response.responseText);
        });
    }

    function buildQuerystring(params) {
        var parts = [];
        for (var k in params) {
            parts.push(
                encodeURIComponent(k) + "=" + encodeURIComponent(params[k])
            );
        }
        return parts.join("&");
    }

    var api = {
        /**
         * Read the session token from the URL. Remove it from the URL if possible.
         * @param {boolean} redirect If true (the default), redirect to the same page without the token.
         * @returns {boolean} Whether a redirect is taking place.
         */
        receiveSessionToken: function (redirect) {
            var match = window.location.search.match(/[?&]token=([^&]+)/);
            if (match) {
                api.setSessionToken(match[1]);
                if (redirect || typeof redirect === "undefined") {
                    window.location.href = window.location.href
                        .replace(/([?&])token=([^&]+)/, "$1")
                        .replace(/\?$/, "");
                    return true;
                }
            }
            return false;
        },
        /**
         * Set our session token.
         * @param {string} token
         */
        setSessionToken: function (token) {
            csrfToken = token;
            sessionStorage.setItem(csrfTokenStorageKey, csrfToken);
        },
        /**
         * Send the user to the authorization endpoint to try to log them in.
         * @param {Record<string,string>} params Extra query params for the endpoint.
         */
        authorize: function (params) {
            if (!params) {
                params = {};
            }
            if (!params.redirect_uri) {
                params.redirect_uri = window.location.href.replace(
                    /([?&])token=([^&]+)/,
                    "$1"
                );
            }
            window.location.href =
                app.baseUrl + "/authorize?" + buildQuerystring(params);
        },
        /**
         * Check if we have a session token.
         * @returns {boolean}
         */
        haveSessionToken: function () {
            return !!csrfToken;
        },
        /**
         * Fetch a fresh access token.
         * @returns {PromiseLike<{ token: string | null, claims: Record<string, unknown> | null }>}
         */
        fetchAccessToken: function () {
            var fetchedAt = new Date().getTime();
            accessTokenCache = xhrFetchJsonWithAuth(
                app.baseUrl + "/token"
            ).then(function (result) {
                if (!result.token) {
                    return { value: result, validUntil: null };
                }
                var validUntil = null;
                var claims = result.claims;
                if (claims && claims.iat && claims.exp) {
                    validUntil = fetchedAt + 1000 * (claims.exp - claims.iat);
                }
                return { value: result, validUntil: validUntil };
            });
            return accessTokenCache.then(function (data) {
                return data.value;
            });
        },
        /**
         * Fetch fresh user info.
         * @returns {PromiseLike<Record<string, unknown> | null>}
         */
        fetchUserInfo: function () {
            userInfoCache = xhrFetchJsonWithAuth(app.baseUrl + "/userinfo");
            return userInfoCache;
        },
        /**
         * Monitor our access token and keep it up-to-date, so getAccessToken() is always fast.
         */
        monitorAccessToken: function () {
            function updateToken() {
                api.fetchAccessToken().then(function () {
                    accessTokenCache.then(function (cache) {
                        var now = new Date().getTime();
                        if (cache.validUntil) {
                            // Update the token some 10 seconds before it expires.
                            var tokenUpdateTimestamp = cache.validUntil - 1000;
                            var timeoutMs = Math.max(
                                10000,
                                tokenUpdateTimestamp - now
                            );
                            // Set a timeout to fetch a new token in X seconds.
                            setTimeout(updateToken, timeoutMs);
                        }
                    });
                });
            }
            updateToken();
        },
        /**
         * Get a valid access token. If we already have one that's valid, we will not fetch a new one.
         * @returns {PromiseLike<{ token: string | null, claims: Record<string, unknown> | null }>}
         */
        getAccessToken: function () {
            if (!accessTokenCache) {
                return api.fetchAccessToken();
            }
            return accessTokenCache.then(function (cache) {
                var now = new Date().getTime();
                if (cache.validUntil && cache.validUntil > now) {
                    return cache.value;
                }
                return api.fetchAccessToken();
            });
        },
        /**
         * Get user info. If we already have user info, we will not fetch new info.
         * @returns {PromiseLike<Record<string, unknown> | null>}
         */
        getUserInfo: function () {
            if (userInfoCache) {
                return userInfoCache;
            }
            return api.fetchUserInfo();
        },
    };
    return api;
})();
