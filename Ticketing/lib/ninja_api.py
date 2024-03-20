""" A collection of helpers to connect and interact with NinjaOne API """

import requests

# Set the NinjaOne Instance you use e.g.:
# eu.ninjarmm.com, app.ninjarmm.com, ca.ninjarmm.com, oc.ninjarmm.com
NINJA_INSTANCE = 'eu.ninjarmm.com'

# Set the board ID to fetch tickets from. By default 2 is the All Tickets Board.
# Please make sure the board you select has:
# Ticket ID, Last Updated, and Tracked Time fields enabled.
BOARD_ID = 2

def connect_ninja_one(client_id, secret):
    """ Authenticate to NinjaOne's API """
    auth_body = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': secret,
        'scope': 'monitoring management' 
    }

    result = requests.post(f"https://{NINJA_INSTANCE}/ws/oauth/token", data=auth_body)

    auth_header = {
        'Authorization': f"Bearer {result.json()['access_token']}"
    }

    return auth_header

def get_ninja_request(path, method, body=None, auth_header=None):
    """ Send a request to NinjaOne's API """
    url = f"https://{NINJA_INSTANCE}{path}"
    headers = auth_header if auth_header else {}
    headers['Content-Type'] = 'application/json'

    if body:
        response = requests.request(method, url, headers=headers, json=body)
    else:
        response = requests.request(method, url, headers=headers)

    return response.json()

def get_ninja_tickets(last_cursor, page_size, board_id, auth_header):
    """ Retrieves the list of tickets from NinjaOne """
    ticket_search = {
        "sortBy": [
            {
                "field": "lastUpdated",
                "direction": "DESC"
            }
        ],
        "pageSize": page_size,
        "lastCursorId": last_cursor
    }

    path = f"/v2/ticketing/trigger/board/{board_id}/run"
    all_tickets = get_ninja_request(path=path, method="POST",
                                    body=ticket_search, auth_header=auth_header)

    return all_tickets

def get_ninja_ticket_details(from_unix, to_unix, auth_header):
    """ Retrieve details for selected tickets """ 
    found = False
    last_cursor = 0
    tickets_list = []

    while not found:
        fetched_tickets = get_ninja_tickets(last_cursor=last_cursor,
                                          page_size=1000, board_id=BOARD_ID,
                                          auth_header=auth_header)

        data_len = len(fetched_tickets["data"])
        print(fetched_tickets["data"][-1])
        if fetched_tickets["data"][-1]["lastUpdated"] < from_unix or data_len == 0:
            found = True
        else:
            last_cursor = fetched_tickets["metadata"]["lastCursorId"]

        tickets_list.extend(fetched_tickets["data"])

    tickets_list_filtered = [ticket for ticket in tickets_list if
                             from_unix <= ticket["lastUpdated"] <= to_unix]

    total_filtered_tickets = len(tickets_list_filtered)
    print(f"Total Tickets to Process: {total_filtered_tickets}")

    processed_ticket_count = 0
    tickets = []

    for ticket_item in tickets_list_filtered:
        processed_ticket_count += 1
        ticket = get_ninja_request(path=f"/v2/ticketing/ticket/{ticket_item['id']}",
                                   method="GET", auth_header=auth_header)

        ticket_logs = None
        if ticket_item["totalTimeTracked"] > 0:
            ticket_logs = get_ninja_request(
                path=f"/v2/ticketing/ticket/{ticket_item['id']}/log-entry",
                method="GET", auth_header=auth_header
            )

        time_entry_users = set()
        if ticket_logs:
            for log_entry in ticket_logs:
                if log_entry["timeTracked"] > 0:
                    time_entry_users.add(log_entry["appUserContactUid"])

        time_entry_user = time_entry_users.pop() if len(time_entry_users) == 1 else None

        total_time = 0
        if ticket_logs:
            time_tracked_list = [
                log_entry["timeTracked"] for log_entry in ticket_logs
                if from_unix <= log_entry["createTime"] <= to_unix
            ]
            total_time_seconds = sum(time_tracked_list)
            total_time_hours = total_time_seconds / 3600
            total_time = round(total_time_hours, 2)

        ticket_data = {
            "TicketID": ticket["ID"],
            "nodeID": ticket["nodeID"],
            "clientID": ticket["clientID"],
            "assignedAppUserID": ticket["assignedAppUserId"],
            "requestorUid": ticket["requesterUid"],
            "Subject": ticket["Subject"],
            "Status": ticket["Status"]["displayName"],
            "Priority": ticket["Priority"],
            "Severity": ticket["Severity"],
            "Form": ticket["ticketFormID"],
            "source": ticket["Source"],
            "tag": ticket["Tags"],
            "createTime": ticket["createTime"],
            "Ticket": ticket,
            "Logs": [log_entry for log_entry in ticket_logs if log_entry["appUserContactUid"] and log_entry["type"] in ['COMMENT', 'DESCRIPTION'] and log_entry["timeTracked"] and from_unix <= log_entry["createTime"] <= to_unix],
            "TimeEntryUID": time_entry_user,
            "TotalTime": total_time
        }

        tickets.append(ticket_data)
        print(f"Processing {processed_ticket_count} / {total_filtered_tickets} Tickets Complete")

    print("Processing Tickets Complete")
    return tickets

def invoke_ninja_one_user_mapping(tickets, users, user_map_loaded):
    """
        Cerca di individuare gli UID per l'ID utente basandosi sui ticket
        in cui solo una persona ha inserito i tempi
        e quindi osservando l'assegnatario del ticket.
    """
    user_mapping_data = [ticket for ticket in tickets if ticket["TimeEntryUID"] is not None and ticket["assignedAppUserID"] is not None]
    user_mapping_data = [{"assignedAppUserID": ticket["assignedAppUserID"], "TimeEntryUID": ticket["TimeEntryUID"], "Merged": f"{ticket['assignedAppUserID']}|{ticket['TimeEntryUID']}"} for ticket in user_mapping_data]
    user_mapping_data = [{k: v for k, v in entry.items() if k != "Merged"} for entry in user_mapping_data]
    user_mapping_data = [{**entry, "Merged": f"{entry['assignedAppUserID']}|{entry['TimeEntryUID']}"} for entry in user_mapping_data]
    user_mapping_data = [{entry["Merged"]: entry} for entry in user_mapping_data]

    user_mapping_data.sort(key=lambda x: x['Merged'], reverse=True)

    user_map = []

    for assigned_user in set(ticket["assignedAppUserID"] for ticket in tickets):
        uid = [uid for uid in user_mapping_data if (uid["Merged"].split('|')[0] == assigned_user) and len(uid) > 1]

        if len(uid) == 1:
            user = next(user for user in users if user["id"] == assigned_user)
            user_map.append({
                "ID": assigned_user,
                "Name": f"{user['firstName']} {user['lastName']}",
                "Email": user["email"],
                "UID": uid[0]["Merged"].split('|')[1]
            })

    if user_map_loaded:
        user_map_filtered = [user for user in user_map if user["ID"] not in user_map_loaded["ID"]]
        user_map = user_map_filtered + user_map_loaded

    return user_map
