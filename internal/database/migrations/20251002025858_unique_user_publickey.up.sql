ALTER TABLE public_keys
ADD CONSTRAINT unique_public_key UNIQUE (public_key);