import * as jose from "node-jose";
import { promises as fsPromise } from "fs";

export async function loadKeystore(): Promise<jose.JWK.KeyStore> {
  const keystore = jose.JWK.createKeyStore();

  if (!process.env.SIGNING_PRIVATE_KEY_PATH) {
    throw new Error("SIGNING_PRIVATE_KEY_PATH: this is required.");
  }

  // Load the signing key.
  const path = process.env.SIGNING_PRIVATE_KEY_PATH;
  const format = process.env.SIGNING_PRIVATE_KEY_FORMAT ?? "pem";
  console.log("Signing key path:", path);
  console.log("Signing key format:", format);

  const buffer = await fsPromise.readFile(path);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await keystore.add(buffer, format as any, {
    use: "sig",
  });

  return keystore;
}
