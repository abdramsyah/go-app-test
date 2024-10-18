CREATE TABLE reset_passwords (
	id bigserial NOT NULL,
	email varchar(255) NOT NULL,
	"token" text NOT NULL,
	status varchar(10) DEFAULT 'unused'::character varying NOT NULL,
	is_clicked bool NOT NULL,
	expires_at timestamp NOT NULL,
	used_at timestamp NULL,
	requested_ip varchar(45) NULL,
	attempt_count int4 DEFAULT 0 NULL,
	created_at timestamp DEFAULT CURRENT_TIMESTAMP NULL,
	updated_at timestamp DEFAULT CURRENT_TIMESTAMP NULL,
	deleted_at timestamp NULL,
	CONSTRAINT reset_passwords_status_check CHECK (((status)::text = ANY ((ARRAY['unused'::character varying, 'used'::character varying])::text[])))
);