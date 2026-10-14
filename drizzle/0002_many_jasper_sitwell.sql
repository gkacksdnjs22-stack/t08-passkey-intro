CREATE TABLE `phone_pairs` (
	`id` text PRIMARY KEY NOT NULL,
	`ticket_hash` text NOT NULL,
	`pc_hash` text NOT NULL,
	`mode` text NOT NULL,
	`user_id` text NOT NULL,
	`handle` text NOT NULL,
	`name` text NOT NULL,
	`storage` text NOT NULL,
	`session_hash` text,
	`state` text DEFAULT 'pending' NOT NULL,
	`credential_id` text,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `phone_pairs_ticket_hash_unique` ON `phone_pairs` (`ticket_hash`);--> statement-breakpoint
ALTER TABLE `passkey_challenges` ADD `pair_id` text;