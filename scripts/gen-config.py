import requests
import json
import argparse
import dotenv
import os

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output", required=True)
parser.add_argument("--validity-period", default=5, type=int)
args = parser.parse_args()

dotenv.load_dotenv()

scoreboard_url = os.environ["SCOREBOARD_URL"]

config = {
    "services": [],
    "teams": [],
    "validity_period": args.validity_period
}

r = requests.get(f"{scoreboard_url}/api/attack.json")
config["flag_regex"] = r.json()["flag_regex"]

r = requests.get(f"{scoreboard_url}/api/scoreboard_service_stats.json")
# best effors
for id,service in enumerate(r.json()["services"]):
    config["services"].append({
        "id": id+1,
        "name": service,
        "flagstores": 1
    })

r = requests.get(f"{scoreboard_url}/api/scoreboard_teams.json")
for id,team in r.json().items():
    config["teams"].append({
        "id": id,
        "name": team["name"],
        "ip": team["vulnbox"],
        "affiliation": team["aff"],
        "website": team["web"],
        "logo": team["logo"] or "",
    })

with open(args.output, "w") as file:
    json.dump(config, file)
