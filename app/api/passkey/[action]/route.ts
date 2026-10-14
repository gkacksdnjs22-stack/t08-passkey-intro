import { authRoute } from '@/lib/passkey';
export const dynamic = 'force-dynamic';
type Context = { params: Promise<{ action: string }> };
async function route(req: Request, ctx: Context) { return authRoute(req,(await ctx.params).action); }
export { route as GET, route as POST, route as DELETE };
