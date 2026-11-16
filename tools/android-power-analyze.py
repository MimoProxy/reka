#!/usr/bin/env python3
"""Summarize a completed, real uncharged A/B run without inventing a power budget."""
import argparse
import datetime
import functools
import json
import math
from pathlib import Path
import statistics


def summarize(report, sys_limit, heap_limit, power_limit):
    if report.get('state') != 'complete' or report.get('diagnostic') or report.get('measurement_kind') != 'uncharged_ab':
        raise ValueError('requires a completed formal uncharged A/B report')
    if report.get('wake_lock') or report.get('artificial_unplug') or not report.get('preflight_passed'):
        raise ValueError('invalid formal measurement conditions')
    phases = {}
    for phase in report['phases']:
        samples = phase['samples']
        if len(samples) < 2 or any(s['plugged'] != 0 or s['screen_interactive'] for s in samples):
            raise ValueError('phase lacks locked, uncharged samples')
        first, last = samples[0], samples[-1]
        seconds = (last['elapsed_ms'] - first['elapsed_ms']) / 1000
        # The installed harness timestamps each sample before PSS/JNI work,
        # then checks its deadline after that work. A completed phase may
        # have a sample span a few ms short of the full deadline interval.
        shortfall_ms = max(0, report['phase_target_seconds']*1000 - (last['elapsed_ms']-first['elapsed_ms']))
        boundary_ms = phase.get('end_elapsed_ms', 0)-phase.get('start_elapsed_ms', 0)
        if boundary_ms and boundary_ms < report['phase_target_seconds']*1000:
            raise ValueError('recorded monotonic phase duration is shorter than target')
        if not boundary_ms and shortfall_ms > 1000:
            raise ValueError('phase sample span is materially shorter than its deadline target')
        charges = [s['charge_uah'] for s in samples]
        steps = [abs(b-a) for a, b in zip(charges, charges[1:]) if b != a]
        quantum = functools.reduce(math.gcd, steps, 0)
        charge = charges[0] - charges[-1]
        current = charge / 1000 / (seconds / 3600)
        memory = {}
        for key in ('sys_mb', 'heap_inuse_mb', 'goroutines'):
            values = [s['go'][key] for s in samples]
            memory[key] = dict(first=values[0], last=values[-1], minimum=min(values), maximum=max(values))
        phases[phase['name']] = dict(samples=len(samples), elapsed_seconds=seconds,
            recorded_boundary_seconds=boundary_ms/1000 if boundary_ms else None, sample_span_shortfall_ms=shortfall_ms, charge_used_mah=charge/1000, average_whole_phone_ma=current,
            counter_quantum_uah=quantum,
            endpoint_quantization_bound_ma=quantum/1000/(seconds/3600),
            process_cpu_percent_of_one_core=(last['process_cpu_ms']-first['process_cpu_ms'])/seconds/10,
            pss_mib=dict(first=first['pss_kib']/1024, last=last['pss_kib']/1024,
                         median=statistics.median(s['pss_kib'] for s in samples)/1024),
            go=memory, temperature_c=dict(first=first['temperature_deci_c']/10,last=last['temperature_deci_c']/10))
    if set(phases) != {'baseline', 'vpn'}:
        raise ValueError('requires one baseline and one VPN phase')
    baseline, vpn = phases['baseline'], phases['vpn']
    delta = vpn['average_whole_phone_ma'] - baseline['average_whole_phone_ma']
    result = dict(measurement_valid=True, application_pid=report['pid'], version=report['version'], phases=phases,
        additional_whole_phone_ma=delta,
        combined_endpoint_quantization_bound_ma=sum(p['endpoint_quantization_bound_ma'] for p in phases.values()),
        memory_budget=dict(max_go_sys_mib=sys_limit,max_go_heap_mib=heap_limit),
        memory_budget_passed=all(p['go']['sys_mb']['maximum'] <= sys_limit and p['go']['heap_inuse_mb']['maximum'] <= heap_limit for p in phases.values()),
        power_budget_max_additional_ma=power_limit,
        power_budget_passed=None if power_limit is None else delta <= power_limit,
        limitations=['Completed harness phases use monotonic deadlines; sample timestamps precede PSS/JNI work (up to 1 s sample-span tolerance, reported explicitly).',
                     'Single sequential whole-phone A/B; temperature, radio and background activity may confound the difference.',
                     'Counter quantization bound is an endpoint rounding bound, not a statistical confidence interval.',
                     'Identical host polling is present in both phases; JNI memory sampling forces GC and FreeOSMemory.',
                     'This report applies to the installed APK provenance; it does not automatically validate later source changes.'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-go-sys-mib', type=float, default=16)
    parser.add_argument('--max-go-heap-mib', type=float, default=4)
    parser.add_argument('--max-additional-ma', type=float)
    args = parser.parse_args()
    result = summarize(json.loads(args.report.read_text()), args.max_go_sys_mib, args.max_go_heap_mib, args.max_additional_ma)
    result['raw_report'] = str(args.report)
    result['analyzed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('measurement_valid','additional_whole_phone_ma','memory_budget_passed','power_budget_passed')}))


if __name__ == '__main__':
    main()
