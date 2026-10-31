CREATE SCHEMA threatinfoservice;

CREATE TABLE threatinfoservice.threats (
    md5 VARCHAR(32) PRIMARY KEY
        CHECK (md5 ~ '^[a-f0-9]{32}$'),

    name VARCHAR(100) NOT NULL
        CHECK (
            char_length(name) BETWEEN 1 AND 100
            AND btrim(name) <> ''
        ),

    description VARCHAR(1000)
        CHECK (
            char_length(description) BETWEEN 1 AND 1000
            AND btrim(description) <> ''
        ),

    severity VARCHAR(20) NOT NULL DEFAULT ''
        CHECK (
            severity IN (
                '',
                'low',
                'medium',
                'high',
                'critical'
            )
        ),

    threat_type VARCHAR(50)
        CHECK (
            char_length(threat_type) BETWEEN 1 AND 50
            AND btrim(threat_type) <> ''
        ),

    detected_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (updated_at >= created_at)
);