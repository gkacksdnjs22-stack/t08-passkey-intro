import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';
export const users = sqliteTable('passkey_users', {
  id: text('id').primaryKey(), handle: text('handle').notNull().unique(), createdAt: text('created_at').notNull(),
});
export const passkeys = sqliteTable('passkeys', {
  id: text('id').primaryKey(), userId: text('user_id').notNull().references(() => users.id),
  publicKey: text('public_key').notNull(), counter: integer('counter').notNull(),
  transports: text('transports').notNull(), name: text('name').notNull(), storage: text('storage').notNull(),
  deviceType: text('device_type').notNull(), backedUp: integer('backed_up').notNull(), createdAt: text('created_at').notNull(), revokedAt: text('revoked_at'),
}, t => [index('passkeys_owner').on(t.userId)]);
export const sessions = sqliteTable('passkey_sessions', {
  hash: text('hash').primaryKey(), userId: text('user_id').notNull().references(() => users.id),
  credentialId: text('credential_id').notNull().references(() => passkeys.id),
  expiresAt: integer('expires_at').notNull(), createdAt: text('created_at').notNull(),
}, t => [index('sessions_user').on(t.userId)]);
export const challenges = sqliteTable('passkey_challenges', {
  id: text('id').primaryKey(), browserHash: text('browser_hash').notNull(), kind: text('kind').notNull(),
  challenge: text('challenge').notNull(), userId: text('user_id').notNull(), handle: text('handle').notNull(),
  name: text('name').notNull(), storage: text('storage').notNull(), sessionHash: text('session_hash'),
  expiresAt: integer('expires_at').notNull(),
});
export const notes = sqliteTable('private_notes', {
  id: text('id').primaryKey(), userId: text('user_id').notNull().references(() => users.id),
  title: text('title').notNull(), content: text('content').notNull(), updatedAt: text('updated_at').notNull(),
}, t => [index('notes_owner').on(t.userId)]);
