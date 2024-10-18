CREATE TABLE permission_groups (
    id bigserial NOT NULL,
    "name" varchar(100) NOT NULL,
    description varchar(255) NULL,
    created_at timestamp NULL DEFAULT now(),
    updated_at timestamp NULL,
    deleted_at timestamp NULL,
    CONSTRAINT permission_groups_pkey PRIMARY KEY (id)
);