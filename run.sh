#!/bin/bash
# run.sh - Lanceur MonitorIA (a copier dans le home, ne pas versionner)
cd /opt/tool_MonitorIA
git restore .
git pull --rebase
chmod +x deploy.sh
./deploy.sh
