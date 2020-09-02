export function isTruthy(value: string | undefined): boolean {
    return (
        typeof value === "string" &&
        (value === "1" ||
            value.toLowerCase() === "true" ||
            value.toLowerCase() === "yes")
    );
}
