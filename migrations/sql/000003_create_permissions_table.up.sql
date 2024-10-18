CREATE TABLE permissions (
    id bigserial NOT NULL,
    permission_group_id int8 NOT NULL,
    "name" varchar(100) NOT NULL,
    description varchar(255) NULL,
    created_at timestamp NULL DEFAULT now(),
    updated_at timestamp NULL,
    deleted_at timestamp NULL,
    CONSTRAINT permissions_pkey PRIMARY KEY (id),
    CONSTRAINT permissions_fk FOREIGN KEY (permission_group_id) REFERENCES permission_groups(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);