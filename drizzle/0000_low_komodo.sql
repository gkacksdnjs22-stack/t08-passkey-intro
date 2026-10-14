CREATE TABLE `passkey_challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`browser_hash` text NOT NULL,
	`kind` text NOT NULL,
	`challenge` text NOT NULL,
	`user_id` text NOT NULL,
	`handle` text NOT NULL,
	`name` text NOT NULL,
	`storage` text NOT NULL,
	`session_hash` text,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `private_notes` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`title` text NOT NULL,
	`content` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `passkey_users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `notes_owner` ON `private_notes` (`user_id`);--> statement-breakpoint
CREATE TABLE `passkeys` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`public_key` text NOT NULL,
	`counter` integer NOT NULL,
	`transports` text NOT NULL,
	`name` text NOT NULL,
	`storage` text NOT NULL,
	`device_type` text NOT NULL,
	`backed_up` integer NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `passkey_users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `passkeys_owner` ON `passkeys` (`user_id`);--> statement-breakpoint
CREATE TABLE `passkey_sessions` (
	`hash` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`credential_id` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `passkey_users`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`credential_id`) REFERENCES `passkeys`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `sessions_user` ON `passkey_sessions` (`user_id`);--> statement-breakpoint
CREATE TABLE `passkey_users` (
	`id` text PRIMARY KEY NOT NULL,
	`handle` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `passkey_users_handle_unique` ON `passkey_users` (`handle`);