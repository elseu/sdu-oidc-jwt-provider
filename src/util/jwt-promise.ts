import * as jsonwebtoken from "jsonwebtoken";

export function sign(
  payload: string | Buffer | Record<string, unknown>,
  secretOrPrivateKey: jsonwebtoken.Secret,
  options?: jsonwebtoken.SignOptions
): Promise<string> {
  return new Promise((resolve, reject) => {
    const callback: jsonwebtoken.SignCallback = (err, result) => {
      if (err || typeof result !== "string") {
        reject(err);
      } else {
        resolve(result);
      }
    };
    if (typeof options === "undefined") {
      jsonwebtoken.sign(payload, secretOrPrivateKey, callback);
    } else {
      jsonwebtoken.sign(payload, secretOrPrivateKey, options, callback);
    }
  });
}

export function verify(
  token: string,
  secretOrPublicKey: jsonwebtoken.Secret | jsonwebtoken.GetPublicKeyOrSecret,
  options?: jsonwebtoken.VerifyOptions
): Promise<Record<string, unknown> | undefined> {
  return new Promise((resolve, reject) => {
    const callback: jsonwebtoken.VerifyCallback = (err, result) => {
      if (err) {
        reject(err);
      } else {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        resolve(result as any);
      }
    };
    if (typeof options === "undefined") {
      jsonwebtoken.verify(token, secretOrPublicKey, callback);
    } else {
      jsonwebtoken.verify(token, secretOrPublicKey, options, callback);
    }
  });
}
