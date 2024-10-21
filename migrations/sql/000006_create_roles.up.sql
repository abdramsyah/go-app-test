CREATE TYPE role_types AS ENUM ('admin','user');
CREATE TABLE roles (
      id bigserial NOT NULL,
      name varchar(100) NOT NULL,
      description varchar(255) NULL,
      role_type role_types NOT NULL DEFAULT 'user'::role_types,
      created_at timestamp NULL DEFAULT now(),
      created_by int8 NULL,
      updated_at timestamp NULL,
      updated_by int8 NULL,
      deleted_at timestamp NULL,
      deleted_by int8 NULL,
      CONSTRAINT roles_pkey PRIMARY KEY (id)
);