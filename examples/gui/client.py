#!/usr/bin/env python3
"""Small native GUI using only the public framed-JSON contract (Python 3/Tk)."""
import argparse
import json
import os
import queue
import socket
import struct
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

MAX_FRAME = 16 << 20


class APIError(Exception):
    def __init__(self, error):
        self.detail = error
        self.code = error.get('code', 'unknown')
        super().__init__(json.dumps(error, ensure_ascii=False))


class Client:
    def __init__(self, address):
        self.lock = threading.Lock()
        self.pending = {}
        self.events = queue.Queue(maxsize=256)
        self.sequence = 0
        self.closed = False
        if address.startswith('pipe://'):
            self.stream = open('\\\\.\\pipe\\' + address[7:], 'r+b', buffering=0)
            self.socket = None
        else:
            self.socket = socket.socket(socket.AF_UNIX)
            self.socket.settimeout(5)
            self.socket.connect(address.removeprefix('unix://'))
            self.socket.settimeout(None)
            self.stream = self.socket.makefile('rwb', buffering=0)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.hello = self.call('Hello', {'versions': [1], 'client': 'reka-example-gui'})
        except Exception:
            self.close()
            raise

    def _exact(self, size):
        out = bytearray()
        while len(out) < size:
            chunk = self.stream.read(size - len(out))
            if not chunk:
                raise ConnectionError('control connection closed')
            out.extend(chunk)
        return bytes(out)

    def _read(self):
        dropped = 0
        try:
            while True:
                size = struct.unpack('>I', self._exact(4))[0]
                if size > MAX_FRAME:
                    raise ValueError('frame exceeds 16 MiB')
                message = json.loads(self._exact(size))
                if 'event' in message:
                    event = message['event']
                    server_dropped = event.get('dropped', 0)
                    event['dropped'] = server_dropped + dropped
                    try:
                        self.events.put_nowait(event)
                        dropped = 0
                    except queue.Full:
                        dropped += 1 + server_dropped
                else:
                    with self.lock:
                        response = self.pending.pop(message.get('id'), None)
                    if response:
                        response.put(message)
        except Exception as exc:
            self._fail(exc)

    def _fail(self, exc):
        with self.lock:
            self.closed = True
            waiting, self.pending = self.pending, {}
        for response in waiting.values():
            response.put(exc)

    def call(self, method, params=None):
        with self.lock:
            if self.closed:
                raise ConnectionError('reconnect before sending changes')
            self.sequence += 1
            ident = self.sequence
            response = queue.Queue(maxsize=1)
            self.pending[ident] = response
            raw = json.dumps({'id': ident, 'method': method, 'params': params or {}}, allow_nan=False).encode()
            try:
                if len(raw) > MAX_FRAME:
                    raise ValueError('request exceeds 16 MiB')
                wire = struct.pack('>I', len(raw)) + raw
                while wire:
                    n = self.stream.write(wire)
                    if not n:
                        raise ConnectionError('short control write')
                    wire = wire[n:]
            except Exception:
                self.pending.pop(ident, None)
                raise
        try:
            result = response.get(timeout=15)
        except queue.Empty:
            self.close()
            raise TimeoutError('request timed out; operation result may need reconciliation')
        if isinstance(result, Exception):
            raise result
        if 'error' in result:
            raise APIError(result['error'])
        return result.get('result')

    def close(self):
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.socket.close()
        self.stream.close()
        self._fail(ConnectionError('client closed'))


def main():
    import tkinter as tk
    from tkinter import ttk
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', required=True, help='unix:///path/control.sock or pipe://reka-service')
    args = parser.parse_args()
    root = tk.Tk()
    root.title('Reka example client')
    root.geometry('960x700')
    executor = ThreadPoolExecutor(max_workers=1)
    results = queue.Queue()
    state = {'client': None, 'revision': 0, 'plan': None, 'pending': None, 'busy': False, 'stale': True}
    banner = tk.StringVar(value='Disconnected')
    ttk.Label(root, textvariable=banner, padding=8).pack(fill='x')
    controls = ttk.Frame(root, padding=8)
    controls.pack(fill='x')
    tabs = ttk.Notebook(root)
    tabs.pack(expand=True, fill='both')
    editors = {}
    for name in ('profile', 'local', 'sources', 'overlay'):
        box = tk.Text(tabs, wrap='none', undo=True)
        tabs.add(box, text=name)
        editors[name] = box
    output = tk.Text(root, height=12, wrap='word')
    output.pack(fill='x')
    buttons = {}

    def show(value):
        output.delete('1.0', 'end')
        output.insert('1.0', json.dumps(value, ensure_ascii=False, indent=2, default=str))

    def documents():
        return {name: box.get('1.0', 'end-1c') for name, box in editors.items()}

    def enable():
        live = state['client'] is not None and not state['client'].closed
        for name, button in buttons.items():
            allowed = not state['busy'] and (name == 'Connect' or live)
            if name == 'Apply':
                allowed = allowed and not state['stale'] and state['plan'] is not None
            if name == 'Retry pending':
                allowed = allowed and state['pending'] is not None
            button.configure(state='normal' if allowed else 'disabled')

    def job(work, success):
        state['busy'] = True
        enable()
        def run():
            try:
                results.put((success, work(), None))
            except Exception as exc:
                results.put((success, None, exc))
        executor.submit(run)

    def loaded(data):
        cfg, status = data
        state.update(revision=cfg['revision'], plan=None, stale=False)
        for name, box in editors.items():
            box.delete('1.0', 'end')
            box.insert('1.0', cfg.get(name, ''))
            box.edit_modified(False)
        banner.set('Connected · revision ' + str(cfg['revision']))
        show(status)

    def load_work():
        c = state['client']
        return c.call('GetConfiguration'), c.call('GetStatus')

    def connect_work():
        old = state['client']
        if old:
            old.close()
        state['client'] = Client(args.control)
        state['client'].call('GetCapabilities')
        state['client'].call('Subscribe')
        return load_work()

    def plan():
        change = dict(documents(), base_revision=state['revision'])
        def planned(result):
            state['plan'] = (change, result)
            show(result)
        job(lambda: state['client'].call('PlanConfiguration', change), planned)

    def applied(result):
        show(result)
        state['pending'] = None
        # A rejected transaction remains visible for review, including diffs.
        if result.get('state') == 'committed':
            job(load_work, loaded)
        else:
            state['stale'] = True

    def apply():
        change, result = state['plan']
        if any(documents()[name] != change[name] for name in editors):
            state['plan'] = None
            show({'message': 'Documents changed after planning; plan again.'})
            enable()
            return
        if result.get('conflict') or result.get('plan', {}).get('blocked') or not result.get('plan_hash'):
            show({'message': 'Resolve the plan diagnostics before applying.', 'plan': result})
            return
        request = dict(change, plan_hash=result['plan_hash'], operation_id='gui-' + uuid.uuid4().hex)
        state['pending'] = request
        job(lambda: state['client'].call('CommitConfiguration', request), applied)

    def retry():
        # Identical operation ID and payload: safe even if the response was lost.
        request = state['pending']
        job(lambda: state['client'].call('CommitConfiguration', request), applied)

    for name, action in [('Connect', lambda: job(connect_work, loaded)), ('Reload', lambda: job(load_work, loaded)), ('Plan', plan), ('Apply', apply), ('Retry pending', retry)]:
        buttons[name] = ttk.Button(controls, text=name, command=action)
        buttons[name].pack(side='left', padx=4)

    def tick():
        try:
            while True:
                callback, value, error = results.get_nowait()
                state['busy'] = False
                if error:
                    state['stale'] = True
                    state['plan'] = None
                    banner.set('State may be stale; reconnect or reload before submitting')
                    show({'error': str(error), 'pending_operation': state['pending']})
                else:
                    callback(value)
        except queue.Empty:
            pass
        c = state['client']
        if c:
            try:
                while True:
                    event = c.events.get_nowait()
                    if event.get('dropped') or (event['type'] in ('config.committed', 'snapshot') and event.get('data', {}).get('revision', state['revision'] + 1) != state['revision']):
                        # Never overwrite an editor while an event is arriving.
                        state['stale'] = True
                        state['plan'] = None
                        banner.set('Configuration changed; reload to obtain the current revision')
            except queue.Empty:
                pass
            if c.closed:
                state['stale'] = True
                banner.set('Disconnected · submissions disabled')
        enable()
        root.after(100, tick)

    def close():
        if state['client']:
            state['client'].close()
        executor.shutdown(wait=False, cancel_futures=True)
        root.destroy()
    root.protocol('WM_DELETE_WINDOW', close)
    tick()
    root.mainloop()


if __name__ == '__main__':
    main()
