CREATE TABLE IF NOT EXISTS stream_offsets (
    stream_name TEXT NOT NULL,
    partition_id INTEGER NOT NULL,
    next_offset BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (stream_name, partition_id)
);
