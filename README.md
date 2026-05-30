# NetGuard: Mini Network Access Policy Checker

NetGuard is a beginner-friendly Python command-line project that checks network
access requests against a small security policy.

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
