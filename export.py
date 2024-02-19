import io
from datetime import datetime
from pathlib import Path

import click
from tenable.nessus import Nessus
from tqdm import tqdm


@click.command()
@click.option(
    "--host", "host", default="https://localhost:8834", help="The Nessus instance"
)
@click.option(
    "--access-key", "access_key", envvar="ACCESS_KEY", help="Nessus API access key"
)
@click.option(
    "--secret-key", "secret_key", envvar="SECRET_KEY", help="Nessus API secret key"
)
@click.option(
    "--identifier",
    "-i",
    "identifier",
    default="SAS_KSB",
    help="String to select the scan(s) to export.",
)
@click.option(
    "--history",
    "history",
    default="1",
    help="Export specific scan from history.",
)
@click.option(
    "--path", "-p", "path", default=".", help="Directory to store the exported files."
)
def export_scans(host, access_key, secret_key, identifier, path, history):
    """Export a Nessus scan or Nessus scans."""
    client = Nessus(url=host, access_key=access_key, secret_key=secret_key)

    # Get all scans
    scans = client.scans.list()

    # Clean scans result and limit data to what's needed
    del scans["timestamp"]
    del scans["folders"]

    relevant_scans = []
    for scan in scans["scans"]:
        if scan["name"].startswith(identifier) and scan["status"] == "completed":
            relevant_scans.append(scan)

    # Create progress bar
    progess_bar = tqdm(relevant_scans)

    # Export scans
    for scan in progess_bar:
        progess_bar.set_description(f'Processing {scan["name"]}')

        scan_history = client.scans.details(scan["id"])['history']

        single_scan = scan_history[-abs(int(history))]

        short_date = datetime.fromtimestamp(single_scan["last_modification_date"]).strftime("%Y%m")
        historic_scan_id = single_scan["history_id"]

        filename = Path(path) / Path(f'{scan["name"]}-{short_date}.nessus')
        scan_data = client.scans.export_scan(scan_id=scan["id"], history_id=historic_scan_id, format="nessus")
        Path(filename).write_bytes(scan_data.getbuffer())


if __name__ == "__main__":
    export_scans()

    # Aufruf
    # python export.py --host "https://localhost:8811" --access-key "key" --secret-key "key" --identifier "SAS_KSB_" --history "1" --path "Path"