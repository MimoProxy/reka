# Dashboard

A small local web page for watching and steering a running kernel: status, groups (click a member to select it), live connections with per-connection rates, route explanations, revision history with restore, and the event stream.

```sh
make dashboard
./bin/reka-dashboard                                  # kernel at the default state root
./bin/reka-dashboard -c unix:///path/to/control.sock  # or REKA_CONTROL=...
```

Open the URL it prints. It includes a one-time token after `#`, which stays in the page and is sent with every request.

The browser cannot reach the control socket, so this program bridges it to HTTP on a loopback address (`-listen`, default `127.0.0.1:9091`). It refuses non-loopback listen addresses, requests without the token, and requests whose `Host` is not a loopback name, so other web pages cannot drive the kernel through the browser. It never reads or writes secrets, and it shows credentials masked.

Selecting a member commits a new revision through plan and commit, exactly like `rekactl select`: groups from a subscription are changed through the overlay, so a refresh keeps the choice. Existing connections keep their outbound; new ones use the new choice. Rates are computed from byte counters of the connections that are still open, so a connection that finished between two refreshes is not counted.
