import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .engine import audit, timestamp


def main(argv=None):
    parser = argparse.ArgumentParser(description='Audit an AWS IAM credential CSV locally; no AWS calls.')
    parser.add_argument('input', type=Path)
    parser.add_argument('--as-of', help='ISO 8601 audit time, including timezone')
    parser.add_argument('--max-key-age', type=int, default=90)
    parser.add_argument('--fail-on', choices=['none', 'high', 'critical'], default='none')
    args = parser.parse_args(argv)
    try:
        result = audit(args.input.read_text(encoding='utf-8-sig'),
                       as_of=timestamp(args.as_of) if args.as_of else datetime.now(timezone.utc),
                       max_key_age=args.max_key_age)
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        print(f'Audit failed: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    blocking = {'none': set(), 'critical': {'critical'}, 'high': {'critical', 'high'}}
    return int(any(f['severity'] in blocking[args.fail_on] for f in result['findings']))
