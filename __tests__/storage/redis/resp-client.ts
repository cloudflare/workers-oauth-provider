import { createConnection, type Socket } from 'node:net';
import type { RedisStorageClient } from '../../../src/storage/redis';

type RespValue = string | number | null | RespValue[];

/** Minimal dependency-free RESP2 client used by the real Redis service test. */
export class RespRedisClient implements RedisStorageClient {
  private socket!: Socket;
  private buffer: Uint8Array<ArrayBufferLike> = new Uint8Array();
  private readonly waiters: Array<{
    resolve(value: RespValue): void;
    reject(error: Error): void;
  }> = [];
  private readonly responses: Array<{ value?: RespValue; error?: Error }> = [];
  private tail: Promise<unknown> = Promise.resolve();
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder();

  static async connect(host: string, port: number): Promise<RespRedisClient> {
    const client = new RespRedisClient();
    client.socket = await new Promise<Socket>((resolve, reject) => {
      const socket = createConnection({ host, port }, () => resolve(socket));
      socket.on('error', reject);
    });
    client.socket.on('data', (chunk) => client.accept(chunk));
    return client;
  }

  get(key: string): Promise<string | null> {
    return this.command(['GET', key]).then((value) => (value === null ? null : String(value)));
  }

  eval(script: string, keys: readonly string[], args: readonly string[]): Promise<unknown> {
    return this.command(['EVAL', script, String(keys.length), ...keys, ...args]);
  }

  flush(): Promise<unknown> {
    return this.command(['FLUSHDB']);
  }

  close(): void {
    this.socket.end();
  }

  private command(parts: readonly string[]): Promise<RespValue> {
    const run = this.tail.then(async () => {
      this.socket.write(encodeCommand(parts, this.encoder));
      return this.next();
    });
    this.tail = run.catch(() => undefined);
    return run;
  }

  private accept(chunk: Uint8Array): void {
    this.buffer = concat(this.buffer, chunk);
    while (true) {
      const parsed = parseResp(this.buffer, 0, this.decoder);
      if (!parsed) return;
      this.buffer = this.buffer.slice(parsed.next);
      const waiter = this.waiters.shift();
      if (parsed.value instanceof Error) {
        if (waiter) waiter.reject(parsed.value);
        else this.responses.push({ error: parsed.value });
      } else if (waiter) waiter.resolve(parsed.value);
      else this.responses.push({ value: parsed.value });
    }
  }

  private next(): Promise<RespValue> {
    const response = this.responses.shift();
    if (response?.error) return Promise.reject(response.error);
    if (response && 'value' in response) return Promise.resolve(response.value!);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
}

function encodeCommand(parts: readonly string[], encoder: TextEncoder): Uint8Array {
  const encoded = parts.map((part) => encoder.encode(part));
  const chunks: Uint8Array[] = [encoder.encode(`*${parts.length}\r\n`)];
  for (const part of encoded) chunks.push(encoder.encode(`$${part.length}\r\n`), part, encoder.encode('\r\n'));
  return chunks.reduce((result, chunk) => concat(result, chunk), new Uint8Array());
}

function parseResp(
  input: Uint8Array<ArrayBufferLike>,
  offset: number,
  decoder: TextDecoder
): { value: RespValue | Error; next: number } | undefined {
  if (offset >= input.length) return undefined;
  const type = String.fromCharCode(input[offset]!);
  const line = readLine(input, offset + 1, decoder);
  if ((type === '+' || type === '-' || type === ':') && !line) return undefined;
  if (type === '+') return { value: line!.value, next: line!.next };
  if (type === '-') return { value: new Error(line!.value), next: line!.next };
  if (type === ':') return { value: Number(line!.value), next: line!.next };
  if (type === '$') {
    if (!line) return undefined;
    const length = Number(line.value);
    if (length === -1) return { value: null, next: line.next };
    if (input.length < line.next + length + 2) return undefined;
    return { value: decoder.decode(input.slice(line.next, line.next + length)), next: line.next + length + 2 };
  }
  if (type === '*') {
    if (!line) return undefined;
    const count = Number(line.value);
    const values: RespValue[] = [];
    let next = line.next;
    for (let index = 0; index < count; index++) {
      const parsed = parseResp(input, next, decoder);
      if (!parsed) return undefined;
      if (parsed.value instanceof Error) return parsed;
      values.push(parsed.value);
      next = parsed.next;
    }
    return { value: values, next };
  }
  throw new Error(`Unsupported RESP type: ${type}`);
}

function readLine(
  input: Uint8Array<ArrayBufferLike>,
  offset: number,
  decoder: TextDecoder
): { value: string; next: number } | undefined {
  for (let index = offset; index + 1 < input.length; index++) {
    if (input[index] === 13 && input[index + 1] === 10) {
      return { value: decoder.decode(input.slice(offset, index)), next: index + 2 };
    }
  }
  return undefined;
}

function concat(left: Uint8Array<ArrayBufferLike>, right: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBufferLike> {
  const result = new Uint8Array(left.length + right.length);
  result.set(left);
  result.set(right, left.length);
  return result;
}
