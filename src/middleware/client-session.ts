export type SessionData = Record<string, unknown>;

export interface ClientSession {
    getData(): SessionData | null;
    setData(data: SessionData | null): void;
}

export interface ClientSessionState {
    clientSession: ClientSession;
}
