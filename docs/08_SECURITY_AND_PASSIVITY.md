# Security and Passive Boundary

The monitored network is strictly read-only.

Forbidden:
- active probing
- scanning
- packet injection
- modifying monitored traffic
- blocking monitored traffic
- initiating communication toward monitored assets

Allowed:
- internal queues
- databases
- application APIs
- dashboards
- local replay/test traffic outside the monitored boundary

AI-generated architecture does not prove real deployment isolation. The team must validate actual network boundaries.
