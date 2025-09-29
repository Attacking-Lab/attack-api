from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool
from os import environ

MIN_CONN = 32
MAX_CONN = 64


def get_conn_str():
    host = environ.get("POSTGRES_HOST", "attack-api-db")
    port = environ.get("POSTGRES_PORT", "5432")
    connstr = f"dbname=postgres user=postgres password=postgres host={host} port={port}"
    print(connstr)
    return connstr


def init_connection_pool() -> AsyncConnectionPool:
    return AsyncConnectionPool(
        get_conn_str(), min_size=MIN_CONN, max_size=MAX_CONN, open=False
    )


async def create_tables(cur: AsyncCursor, drop: bool = False):
    if drop:
        await cur.execute("""
            DROP TABLE IF EXISTS rounds, config, teams, services,
                team_stats, service_stats, attack_info CASCADE;
        """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            name TEXT NOT NULL PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            website TEXT,
            affiliation TEXT,
            logo TEXT
        );
    """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            flagstores INT NOT NULL
        );
    """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS rounds (
            id INTEGER PRIMARY KEY,
            start_ts INTEGER NOT NULL,
            end_ts INTEGER NOT NULL
        );
    """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS team_stats (
            round_id INTEGER,
            team_id INTEGER REFERENCES teams(id),
            points FLOAT NOT NULL,
            rank INTEGER NOT NULL
        );
    """)
    await cur.execute("""
        CREATE INDEX IF NOT EXISTS team_stats_round ON team_stats (round_id)
    """)
    await cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS team_stat_key ON team_stats
            (round_id, team_id);
    """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS service_stats (
            round_id INTEGER,
            team_id INTEGER REFERENCES teams(id),
            service_name TEXT REFERENCES services(name),
            pts_total FLOAT NOT NULL,
            pts_attack FLOAT NOT NULL,
            pts_defense FLOAT NOT NULL,
            pts_sla FLOAT NOT NULL,
            checker_status TEXT NOT NULL,
            flags_lost INT NOT NULL,
            flags_captured INT NOT NULL
        );
    """)
    await cur.execute("""
        CREATE INDEX IF NOT EXISTS service_stats_round ON service_stats (round_id)
    """)
    await cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS service_stats_key ON service_stats
            (round_id, team_id, service_name);
    """)

    await cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_info (
            round_id INTEGER,
            team_id INTEGER REFERENCES teams(id),
            service_name TEXT REFERENCES services(name),
            flagstore_id INTEGER NOT NULL,
            attack_info TEXT
        );
    """)
    await cur.execute("""
        CREATE INDEX IF NOT EXISTS attack_info_round ON attack_info (round_id)
    """)
    await cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS attack_info_key ON attack_info
            (round_id, team_id, service_name, flagstore_id);
    """)

    await cur.execute("""
        CREATE OR REPLACE FUNCTION notify_new_round() RETURNS TRIGGER AS $$
        BEGIN
            PERFORM pg_notify('new_round', NEW.id::text);
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    await cur.execute("DROP TRIGGER IF EXISTS new_round_trigger ON rounds")

    await cur.execute("""
        CREATE TRIGGER new_round_trigger
        AFTER INSERT ON rounds
        FOR EACH ROW
        EXECUTE FUNCTION notify_new_round();
    """)
