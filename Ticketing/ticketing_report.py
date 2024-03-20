""" Query NinjaOne's API to generate ticketing summary report """

from datetime import datetime
import argparse

from lib.utils import date_to_unix_epoch
from lib.ninja_api import (
  connect_ninja_one, get_ninja_request, get_ninja_ticket_details, invoke_ninja_one_user_mapping
)

# Create a machine to machine API application with monitoring
# and management enabled and client_credentials enabled.
# Set the ID and Secret here:
CLIENT_ID = 'Jjl1_XoJYFeMPnDnBzmiu0m4oZo'
API_SECRET = 'j96EO5H2H89GRRTO6X4PEZP6oSR9ssBEYONoDXLOIWCUeI5-tZdt3A'

# Set the location for the ticketing report to be saved.
# By default it will be saved to the folder where the script is run, with the current date appended.
date = datetime.now().strftime("%Y-%m-%d")

def valid_date(date_str):
    """ Verify date's correct format """
    try:
        return datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError as exc:
        msg = f"Formato data non valido: '{date_str}'. Il formato corretto è 'YYYY-MM-DD'"
        raise argparse.ArgumentTypeError(msg) from exc

def main(start_date, end_date):
    """ Main! """
    print(f"Data di inizio: {start_date}")
    print(f"Data di fine: {end_date}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script di esempio con argomenti data")
    parser.add_argument("start_date", type=valid_date, help="Data di inizio (formato: YYYY-MM-DD)")
    parser.add_argument("end_date", type=valid_date, help="Data di fine (formato: YYYY-MM-DD)")

    args = parser.parse_args()
    main(args.start_date, args.end_date)
    start_epoch = date_to_unix_epoch(args.start_date)
    end_epoch = date_to_unix_epoch(args.end_date)
    auth_header = connect_ninja_one(CLIENT_ID, API_SECRET)

    # Fetrch contacts
    contacts = get_ninja_request("/v2/ticketing/contact/contacts", "GET", None, auth_header)

    # Fetch users
    users = get_ninja_request("/v2/users", "GET", None, auth_header)

    # Fetch organizations
    organizations = get_ninja_request("/v2/organizations", "GET", None, auth_header)

    # Fetch Tickets and Comments
    ticket_details = get_ninja_ticket_details(start_epoch, end_epoch, auth_header)
    print(ticket_details)

    invoke_ninja_one_user_mapping(ticket_details)
    #Get-NinjaOneUserSelect
