#!/usr/bin/env sh
# Run ONE internally consistent Option B experiment inside the course-lab `workbench` container.
#
# Usage (inside workbench, from the project root that contains src/):
#   sh tools/run_experiment.sh            # TRIALS=1 (baseline)
#   TRIALS=5 sh tools/run_experiment.sh   # extension run
#
# Produces in /evidence: scope.json result.json experiment.pcap nmap-validation.xml SHA256SUMS commands.txt
# It refuses to overwrite an existing experiment so evidence cannot be silently replaced.
set -eu

SCOPE_SRC=/scopes/assignment-01-tcp-syn-scan.json
EV=${EVIDENCE_DIR:-/evidence}
TRIALS=${TRIALS:-1}
PORTS=22,80,443,8080
TARGET=172.28.70.10

for f in scope.json result.json experiment.pcap nmap-validation.xml SHA256SUMS commands.txt; do
  if [ -e "$EV/$f" ]; then
    echo "refusing to overwrite $EV/$f - move it away first" >&2
    exit 2
  fi
done

cp "$SCOPE_SRC" "$EV/scope.json"
export PYTHONPATH=src

SCAPY_CMD="python3 -m vscan --scope $EV/scope.json --output $EV/result.json --execute --trials $TRIALS"
NMAP_CMD="nmap -sS -Pn -n -p $PORTS --max-retries 1 --max-rate 20 --reason -oX $EV/nmap-validation.xml $TARGET"

{
  echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) experiment commands (executed in order)"
  echo "$SCAPY_CMD"
  echo "$NMAP_CMD"
  echo "# versions"
  python3 -c "import scapy; print('scapy', scapy.__version__)"
  nmap --version | head -n 1
} > "$EV/commands.txt"

echo "== 1/3 start capture (Scapy run only) =="
/opt/course-lab/capture-start experiment.pcap

echo "== 2/3 Scapy scan =="
set +e
$SCAPY_CMD
status=$?
set -e

/opt/course-lab/capture-stop
if [ "$status" -ne 0 ]; then
  echo "scan failed with status $status; not running Nmap or hashing" >&2
  exit "$status"
fi

echo "== 3/3 Nmap validation (separate from the PCAP) =="
$NMAP_CMD

( cd "$EV" && sha256sum scope.json result.json experiment.pcap nmap-validation.xml > SHA256SUMS && cat SHA256SUMS )
echo "done. Copy $EV out of the lab before running reset."
