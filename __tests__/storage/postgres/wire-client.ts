import { createConnection, type Socket } from 'node:net';
import type { PostgresClient, PostgresQueryResult } from '../../../src/storage/postgres';

interface Message {
  readonly type: number;
  readonly payload: Uint8Array;
}

/** Minimal test-only PostgreSQL v3 simple-query client. */
export class PostgresWireClient implements PostgresClient {
  private readonly decoder = new TextDecoder();
  private readonly encoder = new TextEncoder();
  private buffer: Uint8Array<ArrayBufferLike> = new Uint8Array();
  private readonly messages: Message[] = [];
  private readonly waiters: Array<(message: Message) => void> = [];
  private socket!: Socket;

  static async connect(input: {
    host: string;
    port: number;
    user?: string;
    database?: string;
  }): Promise<PostgresWireClient> {
    const client = new PostgresWireClient();
    await client.open(input);
    return client;
  }

  async query<Row = Readonly<Record<string, unknown>>>(
    sql: string,
    values: readonly unknown[] = []
  ): Promise<PostgresQueryResult<Row>> {
    const rendered = sql.replace(/\$(\d+)/g, (_match, index: string) => sqlLiteral(values[Number(index) - 1]));
    const query = this.encoder.encode(`${rendered}\0`);
    this.socket.write(frame('Q'.charCodeAt(0), query));
    let fields: Array<{ name: string; oid: number }> = [];
    const rows: Record<string, unknown>[] = [];
    let rowCount = 0;
    let failure: (Error & { code?: string }) | undefined;
    while (true) {
      const message = await this.next();
      if (message.type === 84) fields = parseFields(message.payload, this.decoder);
      else if (message.type === 68) rows.push(parseRow(message.payload, fields, this.decoder));
      else if (message.type === 67) rowCount = parseRowCount(this.decoder.decode(message.payload));
      else if (message.type === 69) failure = parseError(message.payload, this.decoder);
      else if (message.type === 90) break;
    }
    if (failure) throw failure;
    return { rows: rows as Row[], rowCount };
  }

  release(): void {
    if (this.socket) this.socket.end(frame('X'.charCodeAt(0), new Uint8Array()));
  }

  private async open(input: { host: string; port: number; user?: string; database?: string }): Promise<void> {
    this.socket = await new Promise<Socket>((resolve, reject) => {
      const socket = createConnection({ host: input.host, port: input.port }, () => resolve(socket));
      socket.on('error', reject);
    });
    this.socket.on('data', (chunk) => this.accept(chunk));
    const parameters = this.encoder.encode(
      `user\0${input.user ?? 'postgres'}\0database\0${input.database ?? 'postgres'}\0client_encoding\0UTF8\0\0`
    );
    const startup = new Uint8Array(8 + parameters.length);
    writeInt32(startup, 0, startup.length);
    writeInt32(startup, 4, 196608);
    startup.set(parameters, 8);
    this.socket.write(startup);
    while (true) {
      const message = await this.next();
      if (message.type === 82 && readInt32(message.payload, 0) !== 0) {
        throw new Error('PostgreSQL test server did not accept trust authentication');
      }
      if (message.type === 69) throw parseError(message.payload, this.decoder);
      if (message.type === 90) return;
    }
  }

  private accept(chunk: Uint8Array): void {
    this.buffer = concat(this.buffer, chunk);
    while (this.buffer.length >= 5) {
      const length = readInt32(this.buffer, 1);
      const total = 1 + length;
      if (this.buffer.length < total) return;
      const message = { type: this.buffer[0]!, payload: this.buffer.slice(5, total) };
      this.buffer = this.buffer.slice(total);
      const waiter = this.waiters.shift();
      if (waiter) waiter(message);
      else this.messages.push(message);
    }
  }

  private next(): Promise<Message> {
    const message = this.messages.shift();
    return message ? Promise.resolve(message) : new Promise((resolve) => this.waiters.push(resolve));
  }
}

function frame(type: number, payload: Uint8Array): Uint8Array {
  const output = new Uint8Array(5 + payload.length);
  output[0] = type;
  writeInt32(output, 1, payload.length + 4);
  output.set(payload, 5);
  return output;
}

function sqlLiteral(value: unknown): string {
  if (value === null) return 'NULL';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Non-finite PostgreSQL test parameter');
    return String(value);
  }
  if (typeof value === 'boolean') return value ? 'TRUE' : 'FALSE';
  if (typeof value === 'string') return `'${value.replace(/'/g, "''")}'`;
  throw new TypeError(`Unsupported PostgreSQL test parameter: ${typeof value}`);
}

function parseFields(payload: Uint8Array, decoder: TextDecoder): Array<{ name: string; oid: number }> {
  const count = readInt16(payload, 0);
  let offset = 2;
  const fields = [];
  for (let index = 0; index < count; index++) {
    const name = readCString(payload, offset, decoder);
    offset = name.next + 6;
    const oid = readInt32(payload, offset);
    offset += 12;
    fields.push({ name: name.value, oid });
  }
  return fields;
}

function parseRow(
  payload: Uint8Array,
  fields: Array<{ name: string; oid: number }>,
  decoder: TextDecoder
): Record<string, unknown> {
  const count = readInt16(payload, 0);
  let offset = 2;
  const row: Record<string, unknown> = {};
  for (let index = 0; index < count; index++) {
    const length = readInt32(payload, offset);
    offset += 4;
    const field = fields[index]!;
    if (length === -1) row[field.name] = null;
    else {
      const value = decoder.decode(payload.slice(offset, offset + length));
      offset += length;
      row[field.name] = decodeValue(value, field.oid);
    }
  }
  return row;
}

function decodeValue(value: string, oid: number): unknown {
  if (oid === 3802 || oid === 114) return JSON.parse(value);
  if (oid === 21 || oid === 23 || oid === 700 || oid === 701) return Number(value);
  if (oid === 16) return value === 't';
  return value;
}

function parseRowCount(tag: string): number {
  const match = tag.match(/(?:^| )(\d+)\0?$/);
  return match ? Number(match[1]) : 0;
}

function parseError(payload: Uint8Array, decoder: TextDecoder): Error & { code?: string } {
  let offset = 0;
  const fields: Record<string, string> = {};
  while (payload[offset] !== 0 && offset < payload.length) {
    const code = String.fromCharCode(payload[offset++]!);
    const value = readCString(payload, offset, decoder);
    fields[code] = value.value;
    offset = value.next;
  }
  const error = new Error(fields.M ?? 'PostgreSQL error') as Error & { code?: string };
  error.code = fields.C;
  return error;
}

function readCString(payload: Uint8Array, offset: number, decoder: TextDecoder): { value: string; next: number } {
  let end = offset;
  while (payload[end] !== 0 && end < payload.length) end++;
  return { value: decoder.decode(payload.slice(offset, end)), next: end + 1 };
}

function concat(left: Uint8Array<ArrayBufferLike>, right: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBufferLike> {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

function readInt16(input: Uint8Array, offset: number): number {
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getInt16(offset);
}

function readInt32(input: Uint8Array, offset: number): number {
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getInt32(offset);
}

function writeInt32(output: Uint8Array, offset: number, value: number): void {
  new DataView(output.buffer).setInt32(offset, value);
}
