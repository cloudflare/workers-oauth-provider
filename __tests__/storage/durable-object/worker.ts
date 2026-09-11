/** Test Worker that hosts the storage Durable Object for the Workers vitest pool. */
export { OAuthStorageObject } from '../../../src/storage/durable-object';

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
};
