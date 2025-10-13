from argparse import ArgumentParser
import asyncio
from logging import WARNING, getLogger
from datetime import datetime
import logging
from typing import Annotated, Callable
from dotenv import load_dotenv
import functools

import httpx
from psycopg import AsyncConnection
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Query
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from pydantic import BaseModel, ConfigDict
from collections import defaultdict
from os import environ
from worker_id import *

from database import create_tables, init_connection_pool

load_dotenv()

logger = getLogger(__name__)
logging.basicConfig(level=WARNING)
logger.setLevel(environ.get("ATTACKAPI_LOGLEVEL", "INFO"))

SCOREBOARD_URL = environ["SCOREBOARD_URL"]
CURRENT_API_ENDPOINT = "/api/scoreboard_current.json"
TEAMS_API_ENDPOINT = "/api/scoreboard_teams.json"
CURRENT_SCORE_API_ENDPOINT = "/api/scoreboard.json"
ROUND_SCORE_API_ENDPOINT = "/api/scoreboard_round_{}.json"
CURRENT_ATTACKINFO_API_ENDPOINT = "/api/attack.json"
ROUND_ATTACKINFO_API_ENDPOINT = "/api/attack_round_{}.json"

new_round_id = -1
new_round_ready = asyncio.Event()
new_round_synced = asyncio.Event()

round_synced = set()
attackinfo_synced = set()
round_results_synced = set()

class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Team(StrictBaseModel):
    id: int
    name: str
    ip: str
    website: str | None
    affiliation: str | None
    logo: str | None


class Service(StrictBaseModel):
    id: int
    name: str
    flagstores: int


class CTFConfig(StrictBaseModel):
    teams: dict[int, Team]
    services: dict[int, Service]
    flag_regex: str
    validity_period: int
    service_name_map: dict[str, int]


class CTFDiskConfig(StrictBaseModel):
    teams: list[Team]
    services: list[Service]
    flag_regex: str
    validity_period: int

    def finalize(self) -> CTFConfig:
        teams = {team.id: team for team in self.teams}
        assert len(teams) == len(self.teams)
        services = {service.id: service for service in self.services}
        assert len(services) == len(self.services)
        service_name_map = {service.name: service.id for service in services.values()}
        return CTFConfig(teams=teams, services=services,
                         flag_regex=self.flag_regex,
                         validity_period=self.validity_period,
                         service_name_map=service_name_map)


class CTFState(StrictBaseModel):
    current_round: int = -1
    current_round_start: int = 0


ctf: CTFConfig
state = CTFState()

def httpx_retry(fn: Callable) -> Callable:
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        while True:
            try:
                return await fn(*args, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                logger.warning(f"Request timed out: {e.request.url} (retrying)")
                await asyncio.sleep(1)
            except httpx.HTTPStatusError as e:
                logger.warning(f"Bad response ({e.response.status_code}): {e.request.url} (retrying)")
                await asyncio.sleep(1)
    return wrapper


def list2dict(values: list, keep: int = 1, unique: bool = True):
    layer = defaultdict(lambda: [])
    if len(values) == 0:
        return {}
    for a, *b in values:
        layer[a].append(b[0] if len(b) == 1 else b)
    if len(values[0]) == keep + 1:
        if unique:
            return {a: b for a, b in values}
        return layer
    return {a: list2dict(b, keep=keep, unique=unique) for a, b in layer.items()}


def filterdict(keys, params, value):
    if len(params) == 0:
        return value
    k1, *ks = keys
    p1, *ps = params
    if p1 is not None:
        return filterdict(ks, ps, value[p1])
    data = {}
    for k in k1:
        if k in value:
            data[k] = filterdict(ks, ps, value[k])
    return data


async def database_load_config(conn: AsyncConnection) -> CTFConfig:
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT name, value FROM config WHERE name IN (%s, %s)",
            ("flag_regex", "validity_period"),
        )
        config = {k: v for k, v in await cur.fetchall()}
        flag_regex = config["flag_regex"]
        validity_period = config["validity_period"]

        teams = {}
        await cur.execute(
            "SELECT id, name, ip, website, affiliation, logo " "FROM teams ORDER BY id"
        )
        for id, name, ip, website, affiliation, logo in await cur.fetchall():
            teams[id] = Team(
                id=id,
                name=name,
                ip=ip,
                website=website,
                affiliation=affiliation,
                logo=logo,
            )

        services = {}
        await cur.execute("SELECT id, name, flagstores FROM services " "ORDER BY id")
        for id, name, flagstores in await cur.fetchall():
            services[id] = Service(id=id, name=name, flagstores=flagstores)

    return CTFConfig(
        teams=teams,
        services=services,
        validity_period=validity_period,
        flag_regex=flag_regex,
        service_name_map={v.name: k for k, v in services.items()},
    )


async def database_sync_config(conn: AsyncConnection, config_path: str) -> None:
    with open(config_path) as file:
        config = CTFDiskConfig.model_validate_json(file.read()).finalize()

    async with conn.cursor() as cur:
        for team_id, team in config.teams.items():
            await cur.execute(
                "INSERT INTO teams (id, name, ip, website, affiliation, logo) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, "
                "ip = EXCLUDED.ip, website = EXCLUDED.website, "
                "affiliation = EXCLUDED.affiliation, logo = EXCLUDED.logo",
                (
                    team_id,
                    team.name,
                    team.ip,
                    team.website,
                    team.affiliation,
                    team.logo or None,
                ),
            )

        for service_id, service in config.services.items():
            await cur.execute(
                "INSERT INTO services (id, name, flagstores) VALUES (%s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, flagstores = EXCLUDED.flagstores",
                (service_id, service.name, service.flagstores),
            )

        await cur.executemany(
            "INSERT INTO config (name, value) VALUES (%s, %s) "
            "ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value",
            [
                ("flag_regex", config.flag_regex),
                ("validity_period", config.validity_period),
            ],
        )


@httpx_retry
async def database_sync_next_round():
    global round_synced

    async with conn_pool.connection() as conn:
        async with httpx.AsyncClient(base_url=SCOREBOARD_URL) as client:
            r = await client.get(CURRENT_API_ENDPOINT)
            if r.status_code == 404:
                return False
            r.raise_for_status()
            api_current = r.json()
        new_round_id = api_current["current_tick"]
        new_round_start = api_current["current_tick_start"]

        if new_round_start is None or new_round_id == state.current_round:
            return False

        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM rounds WHERE id = %s", (new_round_id,)
            )
            result = await cur.fetchone()
            if result and result[0]:
                round_synced.add(new_round_id)
                return True

        logger.info(f"Syncing new round {new_round_id} to database")

        async with conn.transaction():
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO rounds (id, start_ts, end_ts) "
                    "VALUES (%s, %s, %s) ON CONFLICT (id) DO NOTHING",
                    (
                        api_current["current_tick"],
                        api_current["current_tick_start"],
                        api_current["current_tick_until"],
                    ),
                )

        round_synced.add(new_round_id)

        # sync the rounds before last in advance (previous would be racy)
        await database_sync_round_attackinfo(conn, new_round_id - 2)
        await database_sync_round_results(conn, new_round_id - 2)

        return True


@httpx_retry
async def database_sync_round_attackinfo(conn: AsyncConnection, round_id: int):
    global attackinfo_synced

    if round_id in attackinfo_synced:
        return True

    logger.info(f"Checking database for attack info for round {round_id}")

    async with conn.transaction():
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"attackinfo_{round_id}",),
            )

            await cur.execute(
                "SELECT 1 FROM attack_info WHERE round_id = %s", (round_id,)
            )
            result = await cur.fetchone()
            if result and result[0]:
                attackinfo_synced.add(round_id)
                return True

            logger.info(f"Updating database with info for round {round_id}")

            async with httpx.AsyncClient(base_url=SCOREBOARD_URL) as client:
                r = await client.get(ROUND_ATTACKINFO_API_ENDPOINT.format(round_id + 1))
                if r.status_code == 404:
                    logger.debug(f"Attackinfo for round {round_id} not available in gameserver")
                    return False
                r.raise_for_status()
                api_attackinfo = r.json()

            for service_name, service_data in api_attackinfo["attack_info"].items():
                for ip, team_data in service_data.items():
                    for round_id, flagstore_data in team_data.items():
                        for flagstore_id, attack_info in flagstore_data.items():
                            await cur.execute(
                                "INSERT INTO attack_info "
                                "(round_id, team_id, service_name, flagstore_id, attack_info) "
                                "SELECT %s, team.id, %s, %s, %s "
                                "FROM teams team WHERE team.ip = %s "
                                "ON CONFLICT (round_id, team_id, service_name, flagstore_id) "
                                "DO UPDATE SET attack_info = EXCLUDED.attack_info",
                                (
                                    round_id,
                                    service_name,
                                    int(flagstore_id),
                                    attack_info,
                                    ip,
                                ),
                            )

    logger.info(f"Completed database update of attack info for round {round_id}")
    attackinfo_synced.add(round_id)

    return True


@httpx_retry
async def database_sync_round_results(conn: AsyncConnection, round_id: int):
    global round_results_synced

    if round_id in round_results_synced:
        return True

    logger.info(f"Checking database for results from round {round_id}")

    async with conn.transaction():
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", (f"results_{round_id}",)
            )

            await cur.execute(
                "SELECT 1 FROM team_stats WHERE round_id = %s", (round_id,)
            )
            result = await cur.fetchone()
            if result and result[0]:
                round_results_synced.add(round_id)
                return True

            logger.debug(f"Updating database with results from round {round_id}...")

            async with httpx.AsyncClient(base_url=SCOREBOARD_URL) as client:
                r = await client.get(ROUND_SCORE_API_ENDPOINT.format(round_id))
                if r.status_code == 404:
                    logger.debug(f"Results for round {round_id} not available in gameserver")
                    return False
                r.raise_for_status()
                api_scores = r.json()

            for team in api_scores["scoreboard"]:
                await cur.execute(
                    "INSERT INTO team_stats (round_id, team_id, points, rank) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (round_id, team_id) DO UPDATE SET points = EXCLUDED.points, rank = EXCLUDED.rank",
                    (round_id, team["team_id"], team["points"], team["rank"]),
                )
                for service_id, service in enumerate(team["services"]):
                    pts_total = service["o"] + service["d"] + service["s"]
                    await cur.execute(
                        "INSERT INTO service_stats "
                        "(round_id, team_id, service_name, pts_total, pts_attack, "
                        "pts_defense, pts_sla, checker_status, flags_lost, flags_captured) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (round_id, team_id, service_name) DO UPDATE SET "
                        "pts_total = EXCLUDED.pts_total, pts_attack = EXCLUDED.pts_attack, "
                        "pts_defense = EXCLUDED.pts_defense, pts_sla = EXCLUDED.pts_sla, "
                        "checker_status = EXCLUDED.checker_status, "
                        "flags_lost = EXCLUDED.flags_lost, flags_captured = EXCLUDED.flags_captured",
                        (
                            round_id,
                            team["team_id"],
                            ctf.services[service_id + 1].name,
                            pts_total,
                            service["o"],
                            service["d"],
                            service["s"],
                            service["c"],
                            service["st"],
                            service["cap"],
                        ),
                    )

    logger.info(f"Completed database update for results from round {round_id}")

    round_results_synced.add(round_id)

    return True


async def database_listen_new_round() -> None:
    global new_round_id
    while True:
        try:
            async with conn_pool.connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("LISTEN new_round;")
                    await conn.commit()
                    gen = conn.notifies()
                    async for event in gen:
                        new_round_id = int(event.payload)
                        logger.info(f"Got new round id: {new_round_id}")
                        new_round_ready.set()
        except:
            await asyncio.sleep(1)
            logger.exception("listen_new_round_id")

async def database_query_new_round() -> None:
    while True:
        try:
            await new_round_ready.wait()
            new_round_ready.clear()
            logger.info(f"Syncing new round {new_round_id} from database")
            async with conn_pool.connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT start_ts FROM rounds WHERE id = %s",
                        (new_round_id,),
                    )
                    round_start, = await cur.fetchone()
            state.current_round = new_round_id
            state.current_round_start = round_start
            logger.info(f"Completed syncing new round {new_round_id}")
            new_round_synced.set()
        except:
            await asyncio.sleep(1)
            logger.exception("query_new_round_id")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ctf, conn_pool
    _ = app
    logger.info("Starting up...")
    conn_pool = init_connection_pool()
    await conn_pool.open()
    async with conn_pool.connection() as conn:
        ctf = await database_load_config(conn)
    await database_sync_next_round()
    scheduler = AsyncIOScheduler()
    await database_sync_next_round()
    if environ["APP_WORKER_ID"] == "1":
        scheduler.add_job(database_sync_next_round, "interval", seconds=1)
    scheduler.add_job(database_listen_new_round)
    scheduler.add_job(database_query_new_round)
    scheduler.start()
    yield
    logger.info("Shutting down...")
    scheduler.shutdown()
    await conn_pool.close()


app = FastAPI(lifespan=lifespan)


async def get_db_conn():
    async with conn_pool.connection() as conn:
        yield conn


class ServicesQuery(StrictBaseModel):
    service: str | None = None


@app.get("/api/v1/services")
async def get_services(req: Annotated[ServicesQuery, Query()]):
    def service_response(service_: Service):
        return {
            "id": service_.id,
            "name": service_.name,
            "flagstores": service_.flagstores,
        }

    response = {}
    if req.service is not None:
        if req.service in ctf.service_name_map:
            return service_response(ctf.services[ctf.service_name_map[req.service]])
    else:
        for service_ in ctf.services.values():
            response[service_.id] = service_response(service_)
    return response


class TeamsQuery(StrictBaseModel):
    team: int | None = None


@app.get("/api/v1/teams")
async def get_teams(req: Annotated[TeamsQuery, Query()]):
    def team_response(team_: Team):
        return {
            "name": team_.name,
            "affiliation": team_.affiliation,
            "logo": team_.logo,
        }

    response = {}
    if req.team is not None:
        if req.team in ctf.teams:
            return team_response(ctf.teams[req.team])
    else:
        for team_ in ctf.teams.values():
            response[team_.id] = team_response(team_)
    return response


class ScoreQuery(StrictBaseModel):
    round: int | None = None
    team: int | None = None
    service: str | None = None


@app.get("/api/v1/score")
async def get_score(req: Annotated[ScoreQuery, Query()], conn=Depends(get_db_conn)):
    round_id = req.round or (state.current_round - 1)
    if not await database_sync_round_results(conn, round_id):
        return {}
    async with conn.cursor() as cur:
        query = """
            SELECT ss.round_id, ss.team_id, ss.service_name,
                ss.pts_total, ss.pts_attack, ss.pts_defense, ss.pts_sla,
                ss.checker_status, ss.flags_lost, ss.flags_captured
            FROM service_stats ss
        """
        filters = []
        variables = []

        filters.append("ss.round_id = %s")
        variables.append(round_id)
        if req.team:
            filters.append("ss.team_id = %s")
            variables.append(req.team)
        if req.service:
            filters.append("ss.service_name = %s")
            variables.append(req.service)

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY (ss.round_id, ss.team_id, ss.service_name)"

        await cur.execute(query, tuple(variables))
        results = await cur.fetchall()

        if len(results) == 0:
            return {}

        results = [
            (
                r,
                t,
                s,
                {
                    "checker": cs,
                    "total": pt,
                    "components": {"attack": pa, "defense": pd, "sla": ps},
                    "flags_gained": fc,
                    "flags_lost": fl,
                },
            )
            for r, t, s, pt, pa, pd, ps, cs, fl, fc in results
        ]

        result_dict = list2dict(results, keep=1)
        keys = list(map(set, list(zip(*results))[:-1]))

        return filterdict(keys, (req.round, req.team, req.service), result_dict)


class AttackInfoQuery(StrictBaseModel):
    round: int | None = None
    team: int | None = None
    service: str | None = None
    flagstore: int | None = None


@app.get("/api/v1/attack_info")
async def get_attack_info(
    req: Annotated[AttackInfoQuery, Query()], conn=Depends(get_db_conn)
):
    round_id = req.round or (state.current_round - 1)
    if not await database_sync_round_attackinfo(conn, round_id):
        return {}
    async with conn.cursor() as cur:
        query = """
            SELECT ai.round_id, ai.team_id, ai.service_name, ai.flagstore_id, ai.attack_info
            FROM attack_info as ai
        """
        filters = []
        variables = []

        filters.append("ai.round_id = %s")
        variables.append(round_id)
        if req.team:
            filters.append("ai.team_id = %s")
            variables.append(req.team)
        if req.service:
            filters.append("ai.service_name = %s")
            variables.append(req.service)
        if req.flagstore:
            filters.append("ai.flagstore_id = %s")
            variables.append(req.flagstore)

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY (ai.round_id, ai.team_id, ai.service_name, ai.flagstore_id)"

        await cur.execute(query, tuple(variables))
        results = await cur.fetchall()
        if len(results) == 0:
            return {}

        result_dict = list2dict(results, keep=1)
        keys = list(map(set, list(zip(*results))[:-1]))

        return filterdict(
            keys, (req.round, req.team, req.service, req.flagstore), result_dict
        )


@app.get("/api/v1/current_round")
async def get_current_round(_: Annotated[StrictBaseModel, Query()]):
    round_start = datetime.fromtimestamp(state.current_round_start).isoformat()
    return {"round": state.current_round, "time": round_start}


@app.get("/api/v1/next_round")
async def get_next_round(_: Annotated[StrictBaseModel, Query()]):
    new_round_synced.clear()
    await new_round_synced.wait()
    new_round_synced.clear()
    round_start = datetime.fromtimestamp(state.current_round_start).isoformat()
    return {"round": state.current_round, "time": round_start}


@app.get("/api/saarctf2024/attack.json")
async def get_saarctf2025_attack_json(
    _: Annotated[StrictBaseModel, Query()], conn=Depends(get_db_conn)
):
    round_id = state.current_round
    for rnd in range(max(0, round_id - ctf.validity_period), round_id):
        await database_sync_round_attackinfo(conn, rnd)

    async with conn.cursor() as cur:
        await cur.execute("SELECT id, name, ip FROM teams ORDER BY id")
        team_ids = [
            {"id": id, "name": name, "ip": ip} for id, name, ip in await cur.fetchall()
        ]

        await cur.execute(
            """
            SELECT ai.service_name, t.ip, ai.round_id, ai.attack_info
            FROM attack_info ai
            JOIN teams t ON ai.team_id = t.id
            WHERE ai.round_id < %s and ai.round_id >= %s
            ORDER BY (ai.service_name, t.ip, ai.round_id, ai.flagstore_id)
        """,
            (round_id, round_id - ctf.validity_period),
        )
        results = await cur.fetchall()

        flag_ids = list2dict(results, keep=1, unique=False)

        return {"teams": team_ids, "flag_ids": flag_ids}


@app.get("/api/faustctf2024/teams.json")
async def get_faust_teams_json(
    _: Annotated[StrictBaseModel, Query()], conn=Depends(get_db_conn)
):
    round_id = state.current_round
    for rnd in range(max(0, round_id - ctf.validity_period), round_id):
        await database_sync_round_attackinfo(conn, rnd)

    async with conn.cursor() as cur:
        team_ids = [team.id for team in ctf.teams.values()]

        await cur.execute(
            """
            SELECT CONCAT(ai.service_name, '-', ai.flagstore_id), ai.team_id, ai.attack_info
            FROM attack_info ai
            WHERE ai.round_id < %s and ai.round_id >= %s
                AND ai.attack_info IS NOT NULL
            ORDER BY (ai.service_name, ai.team_id)
        """,
            (round_id, round_id - ctf.validity_period),
        )
        results = await cur.fetchall()

        flag_ids = list2dict(results, keep=1, unique=False)

        return {"teams": team_ids, "flag_ids": flag_ids}


async def main():
    global ctf, conn_pool
    parser = ArgumentParser()
    parser.add_argument("-c", "--config", required=True)
    parser.add_argument("-d", "--drop", action="store_true", default=False)
    args = parser.parse_args()
    conn_pool = init_connection_pool()
    await conn_pool.open()
    async with conn_pool.connection() as conn:
        async with conn.cursor() as cur:
            await create_tables(cur, drop=args.drop)
        await conn.commit()
        await database_sync_config(conn, args.config)
        await conn.commit()
    await conn_pool.close()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
