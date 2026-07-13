declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

declare module 'node:net' {
  export interface Socket {
    write(data: Uint8Array): boolean;
    end(data?: Uint8Array): void;
    destroy(): void;
    on(event: 'data', listener: (chunk: Uint8Array) => void): this;
    on(event: 'error', listener: (error: Error) => void): this;
    on(event: 'close', listener: () => void): this;
  }
  export function createConnection(options: { host: string; port: number }, listener?: () => void): Socket;
}
