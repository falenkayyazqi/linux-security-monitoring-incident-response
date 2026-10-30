#!/usr/bin/env python3

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta


# Ubuntu auth.log timestamp format:
# 2026-09-25T17:59:04.759749+07:00

TS_PATTERN = (
    r"\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"[+-]\d{2}:\d{2}"
)


FAILED_RE = re.compile(
    rf"(?P<ts>{TS_PATTERN}).*sshd(?:-session)?\[\d+\]: "
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+)"
)


ACCEPTED_RE = re.compile(
    rf"(?P<ts>{TS_PATTERN}).*sshd(?:-session)?\[\d+\]: "
    r"Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+)"
)


SUDO_RE = re.compile(
    rf"(?P<ts>{TS_PATTERN}).*sudo(?:\[\d+\])?:.*"
    r"COMMAND=(?P<command>.*)"
)


def parse_ts(ts_str):
    return datetime.fromisoformat(ts_str)


def parse_cli_ts(value):
    # --since/--until without a UTC offset are treated as local time,
    # so they can be compared with the timezone-aware log timestamps.
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt


def analyze(log_path, threshold, window_minutes, since=None, until=None):

    failed_by_source_user = defaultdict(list)

    failed_events = []
    accepted_events = []
    sudo_events = []
    alerts = []

    with open(log_path, "r", errors="replace") as f:

        for line in f:

            # --------------------------------
            # Failed SSH authentication
            # --------------------------------

            m = FAILED_RE.search(line)

            if m:

                ts = parse_ts(m.group("ts"))

                if since and ts < since:
                    continue

                if until and ts > until:
                    continue

                user = m.group("user")
                ip = m.group("ip")

                key = (ip, user)

                failed_by_source_user[key].append(ts)

                window_start = ts - timedelta(minutes=window_minutes)

                failed_by_source_user[key] = [
                    t
                    for t in failed_by_source_user[key]
                    if t >= window_start
                ]

                failed_events.append({
                    "timestamp": ts.isoformat(),
                    "source_ip": ip,
                    "username": user,
                    "authentication_result": "failed",
                    "authentication_method": "password"
                })

                # Alert only when threshold is reached.
                if len(failed_by_source_user[key]) == threshold:

                    alerts.append({
                        "type": "BRUTE-FORCE ATTEMPT",
                        "timestamp": ts.isoformat(),
                        "source_ip": ip,
                        "username": user,
                        "failed_count_in_window": len(
                            failed_by_source_user[key]
                        ),
                        "window_minutes": window_minutes
                    })

                continue

            # --------------------------------
            # Successful SSH authentication
            # --------------------------------

            m = ACCEPTED_RE.search(line)

            if m:

                ts = parse_ts(m.group("ts"))

                if since and ts < since:
                    continue

                if until and ts > until:
                    continue

                method = m.group("method")
                user = m.group("user")
                ip = m.group("ip")

                accepted_events.append({
                    "timestamp": ts.isoformat(),
                    "source_ip": ip,
                    "username": user,
                    "authentication_result": "success",
                    "authentication_method": method
                })

                key = (ip, user)

                window_start = ts - timedelta(
                    minutes=window_minutes
                )

                recent_failures = [
                    t
                    for t in failed_by_source_user.get(key, [])
                    if t >= window_start
                ]

                # Only successful PASSWORD authentication
                # after repeated failures is considered
                # potentially suspicious.
                if (
                    method == "password"
                    and len(recent_failures) >= threshold
                ):

                    alerts.append({
                        "type":
                            "SUCCESSFUL PASSWORD LOGIN "
                            "AFTER FAILED ATTEMPTS",
                        "timestamp": ts.isoformat(),
                        "source_ip": ip,
                        "username": user,
                        "preceding_failed_count":
                            len(recent_failures),
                        "window_minutes": window_minutes
                    })

                continue

            # --------------------------------
            # Sudo activity
            # --------------------------------

            m = SUDO_RE.search(line)

            if m:

                ts = parse_ts(m.group("ts"))

                if since and ts < since:
                    continue

                if until and ts > until:
                    continue

                sudo_events.append({
                    "timestamp": ts.isoformat(),
                    "command": m.group("command").strip()
                })

    return {
        "analysis_window": {
            "since": since.isoformat() if since else None,
            "until": until.isoformat() if until else None
        },

        "detection_configuration": {
            "threshold": threshold,
            "window_minutes": window_minutes,
            "tracking_key": "source_ip + username"
        },

        "summary": {
            "failed_logins": len(failed_events),
            "accepted_logins": len(accepted_events),
            "sudo_commands": len(sudo_events),
            "alerts_raised": len(alerts)
        },

        "alerts": alerts,
        "failed_logins": failed_events,
        "accepted_logins": accepted_events,
        "sudo_events": sudo_events
    }


def print_summary(result):

    print("=== Log Monitor Summary ===")

    print(
        f"Analysis window        : "
        f"{result['analysis_window']['since']} "
        f"to "
        f"{result['analysis_window']['until']}"
    )

    print(
        f"Failed logins observed   : "
        f"{result['summary']['failed_logins']}"
    )

    print(
        f"Accepted logins observed : "
        f"{result['summary']['accepted_logins']}"
    )

    print(
        f"Sudo commands observed   : "
        f"{result['summary']['sudo_commands']}"
    )

    print(
        f"Alerts raised            : "
        f"{result['summary']['alerts_raised']}"
    )

    print()
    print("=== Alerts ===")

    if not result["alerts"]:

        print("No alerts raised for the given threshold/window.")

    else:

        for alert in result["alerts"]:

            if alert["type"] == "BRUTE-FORCE ATTEMPT":

                print(
                    f"[{alert['timestamp']}] "
                    f"BRUTE-FORCE ATTEMPT "
                    f"from {alert['source_ip']} "
                    f"targeting user "
                    f"'{alert['username']}' "
                    f"({alert['failed_count_in_window']} "
                    f"failures in "
                    f"{alert['window_minutes']} min)"
                )

            elif (
                alert["type"]
                == "SUCCESSFUL PASSWORD LOGIN AFTER FAILED ATTEMPTS"
            ):

                print(
                    f"[{alert['timestamp']}] "
                    f"SUCCESSFUL PASSWORD LOGIN "
                    f"after "
                    f"{alert['preceding_failed_count']} "
                    f"prior failures "
                    f"from {alert['source_ip']} "
                    f"as user '{alert['username']}'"
                )


def main():

    parser = argparse.ArgumentParser(
        description="Simple SSH authentication log monitor"
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to auth.log"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required for alert"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Sliding time window in minutes"
    )

    parser.add_argument(
        "--since",
        help="Analyze logs from this ISO timestamp"
    )

    parser.add_argument(
        "--until",
        help="Analyze logs until this ISO timestamp"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file"
    )

    args = parser.parse_args()

    since = (
        parse_cli_ts(args.since)
        if args.since
        else None
    )

    until = (
        parse_cli_ts(args.until)
        if args.until
        else None
    )

    result = analyze(
        args.log,
        args.threshold,
        args.window,
        since,
        until
    )

    print_summary(result)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print()
    print(f"Results written to: {args.output}")


if __name__ == "__main__":
    main()
