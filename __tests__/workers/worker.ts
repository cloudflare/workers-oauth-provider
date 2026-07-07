const VERIFIED_OAUTH_CONTEXT = Symbol.for('cloudflare.workers-oauth-provider.verified-context.v1');

type SymbolContext = ExecutionContext & Record<symbol, unknown>;

export default {
  fetch(request: Request, _env: unknown, ctx: ExecutionContext) {
    const clientId = new URL(request.url).searchParams.get('clientId') ?? 'unknown';
    const value = { clientId };
    const symbolContext = ctx as SymbolContext;
    const hadExistingValue = VERIFIED_OAUTH_CONTEXT in ctx;

    Object.defineProperty(ctx, VERIFIED_OAUTH_CONTEXT, {
      value,
      enumerable: false,
      writable: false,
      configurable: false,
    });

    let assignmentThrew = false;
    try {
      symbolContext[VERIFIED_OAUTH_CONTEXT] = { clientId: 'attacker' };
    } catch (error) {
      assignmentThrew = error instanceof TypeError;
    }

    const descriptor = Object.getOwnPropertyDescriptor(ctx, VERIFIED_OAUTH_CONTEXT);
    return Response.json({
      hadExistingValue,
      preservesIdentity: symbolContext[VERIFIED_OAUTH_CONTEXT] === value,
      assignmentThrew,
      enumerable: descriptor?.enumerable,
      writable: descriptor?.writable,
      configurable: descriptor?.configurable,
      appearsInKeys: Object.keys(ctx).includes(clientId),
      appearsInSpread: Object.values({ ...ctx }).includes(value),
      appearsInJson: JSON.stringify(ctx).includes(clientId),
      clientId: (symbolContext[VERIFIED_OAUTH_CONTEXT] as { clientId: string }).clientId,
    });
  },
};
