#!/usr/bin/env python3
"""Authorized sleep/wake hook: one owned alarm, no changes to other schedules."""
import datetime
import json
import os
import subprocess
import time


def run(*command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=20).strip()


def main():
    if os.geteuid() != 0:
        raise RuntimeError('administrator privileges required')
    owner = 'org.mimoproxy.reka.acceptance.' + str(os.getpid())
    alarm = (datetime.datetime.now() + datetime.timedelta(seconds=45)).strftime('%m/%d/%y %H:%M:%S')
    before = run('/usr/sbin/sysctl', '-n', 'kern.waketime')
    start = time.time()
    run('/usr/bin/pmset', 'schedule', 'wakeorpoweron', alarm, owner)
    try:
        run('/usr/bin/pmset', 'sleepnow')
        after = before
        while time.time() - start < 100:
            time.sleep(1)
            after = run('/usr/sbin/sysctl', '-n', 'kern.waketime')
            if after != before:
                break
        if after == before:
            raise RuntimeError('actual system wake was not observed')
        print(json.dumps(dict(wake_before=before, wake_after=after,
                              wall_seconds=time.time() - start, alarm_owner=owner)))
    finally:
        # The event may already have fired. Never cancel unrelated events.
        subprocess.run(['/usr/bin/pmset', 'schedule', 'cancel', 'wakeorpoweron', alarm, owner],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)


if __name__ == '__main__':
    main()
