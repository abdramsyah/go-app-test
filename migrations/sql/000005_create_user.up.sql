CREATE TABLE "users" (
  "id" BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY NOT NULL,
  "email" varchar(100) UNIQUE NOT NULL,
  "name" varchar(100) NOT NULL,
  "role_id" bigint,
  "username" varchar(100) NOT NULL,
  "password_hash" varchar(100) NOT NULL,
  "phone_number" varchar(20) NOT NULL,
  "created_by" bigint,
  "updated_by" bigint,
  "deleted_by" bigint,
  "created_at" timestamp NOT NULL,
  "updated_at" timestamp NOT NULL,
  "deleted_at" timestamp
);
