import { defineOAuthStorageCapabilities, type OAuthStorageCapabilities } from './capabilities';
import type {
  OAuthAccessTokenStore,
  OAuthClientStore,
  OAuthConsentStore,
  OAuthGrantStore,
  OAuthMaintenanceStore,
  OAuthReplayStore,
} from './stores';

/** A value or promise accepted by storage lifecycle hooks. */
export type Awaitable<T> = T | PromiseLike<T>;

/** Stable kind of request-scoped storage operation. */
export type OAuthStorageOperationKind = 'request' | 'helper' | 'maintenance';

/** Context supplied whenever the OAuth engine opens a storage connection. */
export interface OAuthStorageOpenContext<Env> {
  /** Worker environment for this request or helper call. */
  readonly env: Env;
  /** Optional Workers execution context for request-local deferred work. */
  readonly executionContext?: ExecutionContext;
  /** Fixed logical namespace configured by the provider. */
  readonly namespace: string;
  /** Stable non-secret identifier used only for tracing one open connection. */
  readonly operationId: string;
  /** Distinguishes endpoint handling from public helpers and cleanup. */
  readonly kind: OAuthStorageOperationKind;
  /** Optional cancellation signal. */
  readonly signal?: AbortSignal;
}

/** Request-scoped normalized access to all OAuth domain stores. */
export interface OAuthStorageConnection {
  /** Logical namespace this connection is authorized to access. */
  readonly namespace: string;
  readonly clients: OAuthClientStore;
  readonly grants: OAuthGrantStore;
  readonly accessTokens: OAuthAccessTokenStore;
  readonly consents: OAuthConsentStore;
  readonly replay: OAuthReplayStore;
  readonly maintenance: OAuthMaintenanceStore;
  /** Releases request-scoped resources. The engine calls this exactly once. */
  close(): Awaitable<void>;
}

/** Configured backend implementation with a stable static capability descriptor. */
export interface OAuthStorageProvider<Env = Cloudflare.Env> {
  /** Stable adapter identifier, for example `cloudflare-kv` or `d1`. */
  readonly id: string;
  /** Storage contract version implemented by this adapter. */
  readonly contractVersion: 1;
  /** Fixed logical namespace, defaulting to `default` in built-in factories. */
  readonly namespace: string;
  /** Guarantees available before opening a backend connection. */
  readonly capabilities: OAuthStorageCapabilities;
  /** Opens one request- or operation-scoped normalized connection. */
  open(context: OAuthStorageOpenContext<Env>): Awaitable<OAuthStorageConnection>;
}

/** Validates a logical storage namespace and returns its canonical form. */
export function defineStorageNamespace(namespace = 'default'): string {
  if (
    namespace.length < 1 ||
    namespace.length > 128 ||
    namespace.trim() !== namespace ||
    /[\u0000-\u001f\u007f]/.test(namespace)
  ) {
    throw new TypeError('Storage namespace must be bounded and contain no control or surrounding whitespace');
  }
  return namespace;
}

/** Validates a provider's static identity, contract version, namespace, and capabilities. */
export function validateOAuthStorageProvider<Env>(provider: OAuthStorageProvider<Env>): void {
  if (!/^[a-z][a-z0-9.-]{0,63}$/.test(provider.id)) {
    throw new TypeError('Storage adapter ID must be a stable lowercase identifier');
  }
  if (provider.contractVersion !== 1) throw new TypeError('Unsupported OAuth storage contract version');
  defineStorageNamespace(provider.namespace);
  defineOAuthStorageCapabilities(provider.capabilities);
  if (typeof provider.open !== 'function') throw new TypeError('Storage provider must define open()');
}

/** Creates an open context whose namespace is taken from the validated provider. */
export function createOAuthStorageOpenContext<Env>(input: {
  readonly provider: OAuthStorageProvider<Env>;
  readonly env: Env;
  readonly operationId: string;
  readonly kind: OAuthStorageOperationKind;
  readonly executionContext?: ExecutionContext;
  readonly signal?: AbortSignal;
}): OAuthStorageOpenContext<Env> {
  validateOAuthStorageProvider(input.provider);
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(input.operationId)) {
    throw new TypeError('Storage operation ID must be a bounded non-secret identifier');
  }
  if (input.kind !== 'request' && input.kind !== 'helper' && input.kind !== 'maintenance') {
    throw new TypeError('Invalid storage operation kind');
  }
  return Object.freeze({
    env: input.env,
    namespace: input.provider.namespace,
    operationId: input.operationId,
    kind: input.kind,
    ...(input.executionContext === undefined ? {} : { executionContext: input.executionContext }),
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
}

/** Rejects a connection that opened a different logical namespace. */
export function assertStorageConnectionNamespace(
  provider: Pick<OAuthStorageProvider<unknown>, 'namespace'>,
  connection: Pick<OAuthStorageConnection, 'namespace'>
): void {
  if (connection.namespace !== provider.namespace) {
    throw new TypeError('Storage connection namespace does not match its provider');
  }
}
