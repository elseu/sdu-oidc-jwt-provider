import * as zlib from "zlib";
import { promisify } from "util";

type Charset = "utf-8" | "base64" | "ascii";

interface Charsets {
    from: Charset;
    to: Charset;
}

const gzip = promisify<Buffer, Buffer>(zlib.gzip);
const gunzip = promisify<Buffer, Buffer>(zlib.gunzip);

export async function compress<T extends string | undefined | Buffer>(
    data: T
): Promise<T> {
    return operate(data, { from: "utf-8", to: "base64" }, async (buffer) => {
        const output = await gzip(buffer);
        console.log(`${buffer.length} => ${output.length}`);
        return output;
    });
}

export async function decompress<T extends string | undefined | Buffer>(
    data: T
): Promise<T> {
    return operate(
        data,
        { from: "base64", to: "utf-8" },
        async (buffer) => await gunzip(buffer)
    );
}

async function operate<T extends string | undefined | Buffer>(
    data: T,
    charsets: Charsets,
    callback: (buffer: Buffer) => Promise<Buffer>
): Promise<T> {
    if (typeof data === "undefined") {
        return data;
    }
    if (typeof data === "string") {
        return (await callback(Buffer.from(data, charsets.from))).toString(
            charsets.to
        ) as T;
    }
    return (await callback(data as Buffer)) as T;
}
