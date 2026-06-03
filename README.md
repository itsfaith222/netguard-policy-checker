# NetGuard: Mini Network Access Policy Checker

NetGuard is a beginner-friendly Python project that checks network access
requests against a small security policy. It can run as a command-line report or
as a local Flask dashboard at `http://127.0.0.1:5000`.

It demonstrates common network security engineering ideas:

- VLANs as network zones
- Subnets as address ranges inside those zones
- Firewall-style allow and deny rules
- Least privilege access
- Default deny behavior
- Network segmentation between user groups

## Project Structure

```text
.
├── data/
│   └── requests.csv
├── static/
│   └── style.css
├── templates/
│   └── index.html
├── app.py
├── main.py
├── policy.py
├── test_policy.py
├── README.md
└── requirements.txt
```

## Policy Rules

1. Employee devices on VLAN 10 can access `internal_app` on port `443`.
2. Guest devices on VLAN 30 can only access `internet` on ports `80` and `443`.
3. Security devices on VLAN 20 can access `logging_server` on port `514` and `internal_app` on port `443`.
4. Admin devices on VLAN 40 can access `admin_panel` on port `22`.
5. Unknown devices are denied by default.
6. Guest devices can never access `file_server`, `admin_panel`, or `logging_server`.

## CSV Format

The tool reads requests from `data/requests.csv`.

```csv
device_name,device_type,vlan,source_ip,destination,port
employee-laptop-01,employee,10,10.10.5.21,internal_app,443
guest-phone-01,guest,30,10.30.8.44,internet,443
```

## Setup

Create a virtual environment if you want to keep dependencies isolated:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run the Tool

```powershell
python main.py
```

Or pass a custom CSV file:

```powershell
python main.py data/requests.csv
```

Example output:

```text
NetGuard Access Policy Report
==========================================================================================
Device             Type       VLAN   Source IP       Destination     Port   Result  Reason
------------------------------------------------------------------------------------------
employee-laptop-01 employee   10     10.10.5.21      internal_app    443    ALLOW   Employees may use the internal app over HTTPS.
guest-laptop-03    guest      30     10.30.8.46      admin_panel     22     DENY    Guest VLAN is segmented away from admin_panel; guests may only access internet ports 80 and 443.
```

## Run the Dashboard

Install dependencies first:

```powershell
pip install -r requirements.txt
```

Start the local Flask app:

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The dashboard reads `data/requests.csv`, checks each row with the policy logic in
`policy.py`, and displays the results in a table. It shows:

- Device name, device type, IP address, VLAN, requested resource, and port
- `ALLOW` or `DENY` decision for each request
- A plain-English reason for each decision
- Summary cards for total, allowed, denied, and most suspicious request
- Filters for all requests, allowed requests, denied requests, and VLAN

The processed data is also available as JSON:

```text
http://127.0.0.1:5000/api/requests
```

The API supports the same filters:

```text
http://127.0.0.1:5000/api/requests?decision=denied&vlan=30
```

## Run Tests

```powershell
pytest
```

## Learning Notes

VLANs divide a network into separate zones. In this project, employees, guests,
security devices, and admins each have their own VLAN.

Least privilege means each device type only gets the access it needs. For
example, guest devices can browse the internet but cannot reach admin or logging
systems.

Default deny means the program denies traffic unless a rule explicitly allows it.
This is safer than allowing unknown traffic by accident.

The Flask dashboard connects the browser to the existing Python policy code.
`app.py` loads the CSV rows, converts each row into an `AccessRequest`, calls
`evaluate_request()`, and sends the processed rows to `templates/index.html`.

The table rows come from `data/requests.csv`. Python reads each CSV line as a
dictionary, validates fields such as VLAN and port, and turns the result into a
display-friendly row with a decision and reason.

The allow/deny decision is calculated with a default-deny model. A request is
allowed only when its device type, VLAN, destination, and port match an explicit
rule in `policy.py`.

This demonstrates network segmentation and firewall rules because each VLAN is
treated as a separate network zone. The rules show how traffic between zones and
resources can be limited to only what each device role needs.

## What I Learned

- How to separate policy logic from presentation code
- How Flask routes can render HTML pages and return JSON APIs
- How CSV data can become Python objects and then dashboard table rows
- How default-deny firewall thinking reduces unnecessary network access
