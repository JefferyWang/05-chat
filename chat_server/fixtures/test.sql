-- insert workspaces
INSERT INTO workspaces (name, owner_id) VALUES
    ('acme', 0),
    ('foo', 0),
    ('bar', 0);

-- insert users
INSERT INTO users (ws_id, email, fullname, password_hash)
    VALUES (1, 'tchen@acme.org', 'Tyr Chen', '$argon2id$v=19$m=19456,t=2,p=1$3uxN483oYKTEGEQw3AED7A$QVJHKIyVuq4sEO5NDwVMYxWwejgPV7fBAXH0bgP0mX4'),
    (1, 'alice@acme.org', 'Alice Chen', '$argon2id$v=19$m=19456,t=2,p=1$3uxN483oYKTEGEQw3AED7A$QVJHKIyVuq4sEO5NDwVMYxWwejgPV7fBAXH0bgP0mX4'),
    (1, 'bob@acme.org', 'Bob Chen', '$argon2id$v=19$m=19456,t=2,p=1$3uxN483oYKTEGEQw3AED7A$QVJHKIyVuq4sEO5NDwVMYxWwejgPV7fBAXH0bgP0mX4'),
    (1, 'charlie@acme.org', 'Charlie Chen', '$argon2id$v=19$m=19456,t=2,p=1$3uxN483oYKTEGEQw3AED7A$QVJHKIyVuq4sEO5NDwVMYxWwejgPV7fBAXH0bgP0mX4'),
    (1, 'daisy@acme.org', 'Daisy Chen', '$argon2id$v=19$m=19456,t=2,p=1$3uxN483oYKTEGEQw3AED7A$QVJHKIyVuq4sEO5NDwVMYxWwejgPV7fBAXH0bgP0mX4');

-- insert chats
INSERT INTO chats (ws_id, name, type, members)
    VALUES (1, 'general', 'public_channel', '{1,2,3,4,5}'),
           (1, 'private', 'private_channel', '{1,2,3}');

-- insert unnamed chat
INSERT INTO chats (ws_id, type, members)
    VALUES (1, 'single', '{1,2}'),
           (1, 'group', '{1,3,4}');
