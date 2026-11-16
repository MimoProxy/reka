#!/usr/bin/env python3
"""Validate three protocols against temporary reference nodes on Windows.

Only the supplied client IP can reach the temporary inbound firewall rules.
An independent scheduled cleanup bounds exposure if SSH or the client fails.
Credentials stay in private generated files and never enter the report.
"""
import argparse
import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--user', required=True)
    p.add_argument('--host-key-alias', required=True)
    p.add_argument('--client-ip', required=True)
    p.add_argument('--server', type=Path, default=ROOT / 'bin/reference-node-windows.exe')
    p.add_argument('--client', type=Path, default=ROOT / 'bin/livenodes')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    ipaddress.ip_address(a.host)
    ipaddress.ip_address(a.client_ip)
    if not a.user.isalnum():
        p.error('user must be an account name')
    os.umask(0o077)
    name = 'remote-nodes-' + uuid.uuid4().hex
    local = ROOT / 'bin/private' / name
    local.mkdir(parents=True)
    remote = 'C:/Users/' + a.user + '/AppData/Local/RekaAcceptance/' + name
    win = remote.replace('/', '\\')
    target = a.user + '@' + a.host
    options = ['-o', 'HostKeyAlias=' + a.host_key_alias, '-o', 'ConnectTimeout=8']

    def ps(code, timeout=90):
        code = "$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); " + code
        encoded = base64.b64encode(code.encode('utf-16le')).decode()
        r = subprocess.run(['ssh', *options, target, 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + encoded], capture_output=True, text=True, errors='replace', timeout=timeout)
        if r.returncode:
            (local / 'remote-error.log').write_text(r.stdout + r.stderr)
            raise RuntimeError('Remote setup failed; inspect the private remote-error.log')
        return r.stdout

    password = secrets.token_urlsafe(32)
    user_uuid = str(uuid.uuid4())
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(local / 'key.pem'), '-out', str(local / 'cert.pem'), '-days', '1', '-subj', '/CN=reka-controlled.test'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = {'enabled': True, 'certificate_path': win + '\\cert.pem', 'key_path': win + '\\key.pem'}
    inbounds = []
    proxies = []
    for typ, port in [('trojan', 39381), ('hysteria2', 39382), ('tuic', 39383)]:
        inbound = {'type': typ, 'tag': typ, 'listen': a.host, 'listen_port': port, 'tls': dict(tls)}
        user = {'password': password}
        if typ == 'tuic':
            user['uuid'] = user_uuid
            inbound['congestion_control'] = 'cubic'
        if typ != 'trojan':
            inbound['tls']['alpn'] = ['h3']
        inbound['users'] = [user]
        inbounds.append(inbound)
        proxy = {'name': typ, 'type': typ, 'server': a.host, 'port': port, 'password': password, 'sni': 'reka-controlled.test', 'skip-cert-verify': True, 'udp': True}
        if typ == 'tuic':
            proxy.update(uuid=user_uuid, alpn=['h3'], **{'congestion-controller': 'cubic'})
        proxies.append(proxy)
        denied=copy.deepcopy(proxy)
        denied['name']=typ+'-authentication-denied'
        denied['password']=secrets.token_urlsafe(32)
        proxies.append(denied)
    (local / 'config.json').write_text(json.dumps({'log': {'level': 'debug', 'timestamp': True, 'output': win + '\\server.log'}, 'dns': {'servers': [{'type': 'local', 'tag': 'test-local'}]}, 'route': {'default_domain_resolver': {'server': 'test-local', 'strategy': 'ipv4_only'}}, 'inbounds': inbounds, 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}))
    (local / 'client.json').write_text(json.dumps({'proxies': proxies}))
    cleanup = """$ErrorActionPreference='Continue'
$root='ROOT'
$exe=Join-Path $root 'reference.exe'
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $exe } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Get-NetFirewallRule -Group 'GROUP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Unregister-ScheduledTask -TaskName 'GROUP-server' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'GROUP' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item (Join-Path $root 'key.pem'),(Join-Path $root 'config.json') -Force -ErrorAction SilentlyContinue
""".replace('ROOT', win).replace('GROUP', name)
    (local / 'cleanup.ps1').write_text(cleanup)
    report = {'kind': 'independent_remote_LAN_reference_nodes', 'reference': 'sing-box v1.14.4', 'remote_target_resolution': 'IPv4 only (controlled test path)', 'firewall_scope': 'one explicitly supplied client IP', 'tls': 'one-day generated self-signed test certificate', 'results': []}
    created = False
    try:
        ps("$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Path '" + win + "' | Out-Null")
        created = True
        for source, dest in [(a.server, 'reference.exe'), (local / 'config.json', 'config.json'), (local / 'cert.pem', 'cert.pem'), (local / 'key.pem', 'key.pem'), (local / 'cleanup.ps1', 'cleanup.ps1')]:
            subprocess.run(['scp', *options, str(source), target + ':' + remote + '/' + dest], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        # Register recovery before opening a listener or firewall rule.
        start = """$ErrorActionPreference='Stop'
$root='ROOT'
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$root+'\\cleanup.ps1"')
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15)
Register-ScheduledTask -TaskName 'GROUP' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest | Out-Null
New-NetFirewallRule -DisplayName 'GROUP TCP' -Group 'GROUP' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 'SERVERIP' -LocalPort 39381 -RemoteAddress 'CLIENTIP' -Program (Join-Path $root 'reference.exe') | Out-Null
New-NetFirewallRule -DisplayName 'GROUP UDP' -Group 'GROUP' -Direction Inbound -Action Allow -Protocol UDP -LocalAddress 'SERVERIP' -LocalPort 39382,39383 -RemoteAddress 'CLIENTIP' -Program (Join-Path $root 'reference.exe') | Out-Null
$serverAction=New-ScheduledTaskAction -Execute (Join-Path $root 'reference.exe') -Argument ('run -c "'+$root+'\\config.json"') -WorkingDirectory $root
Register-ScheduledTask -TaskName 'GROUP-server' -Action $serverAction -User 'SYSTEM' -RunLevel Highest | Out-Null
Start-ScheduledTask -TaskName 'GROUP-server'
Start-Sleep -Seconds 2
if (@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq (Join-Path $root 'reference.exe') }).Count -ne 1) { throw 'Reference server exited before validation' }
Write-Output 'reference_started'
""".replace('ROOT', win).replace('GROUP', name).replace('SERVERIP', a.host).replace('CLIENTIP', a.client_ip)
        ps(start)
        result = subprocess.run([str(a.client), '-config', str(local / 'client.json'), '-per-type', '2', '-diagnostic'], capture_output=True, text=True, timeout=150)
        (local / 'client-diagnostic.log').write_text(result.stderr)
        report['results'] = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        (local / 'server-diagnostic.log').write_text(ps("Get-Content -Raw -Path '" + win + "\\server.log' -ErrorAction SilentlyContinue; Write-Output 'log_end'"))
        report['includes_wrong_password_negatives'] = True
        report['https_client'] = 'HTTP/2 enabled; local HTTP/1.1 over TLS regression also required'
        report['passed'] = result.returncode == 0 and len(report['results']) == 6 and all((r.get('tcp') == 'passed' and r.get('http_status') == 204 and r.get('udp') == 'passed') if r['index'] == 1 else (r.get('tcp') == 'http-request-failed' and r.get('udp') in ('dial-failed', 'exchange-failed')) for r in report['results'])
    finally:
        if created:
            try:
                ps(cleanup)
                verify = ps("$ErrorActionPreference='Stop'; $r=@(Get-NetFirewallRule -Group '" + name + "' -ErrorAction SilentlyContinue); $t=@(Get-ScheduledTask -TaskName '" + name + "','" + name + "-server' -ErrorAction SilentlyContinue); $p=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq '" + win + "\\reference.exe' }); if ($r.Count -ne 0 -or $t.Count -ne 0 -or $p.Count -ne 0) {throw 'Cleanup verification failed'}; Write-Output 'restored'")
                report['restored'] = 'restored' in verify
                if report['restored']:
                    ps("Remove-Item -LiteralPath '" + win + "' -Recurse -Force -ErrorAction Stop")
            except Exception:
                report['restored'] = False
        for filename in ('key.pem', 'config.json', 'client.json'):
            (local / filename).unlink(missing_ok=True)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report.get('passed') and report.get('restored') else 1


if __name__ == '__main__':
    raise SystemExit(main())
