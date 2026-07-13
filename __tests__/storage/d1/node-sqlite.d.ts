declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string);
    exec(sql: string): void;
    prepare(sql: string): {
      run(...values: unknown[]): { changes: number; lastInsertRowid: number | bigint };
      all(...values: unknown[]): Record<string, unknown>[];
      get(...values: unknown[]): Record<string, unknown> | undefined;
    };
    close(): void;
  }
}
