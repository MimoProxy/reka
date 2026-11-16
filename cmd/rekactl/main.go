// Command rekactl controls a running Reka kernel through its control API.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/platform"
)

const usage = `usage: rekactl [-c address | -state-root dir] [-json] command [args]

configuration
  get [profile|local|sources|overlay|effective] [-reveal]   print the active configuration
  subscription list|set ID URL|refresh ID|pause ID|resume ID|remove ID
  import -source ID [-format auto|clash|links] [-nodes-only] [-allow-partial] [-apply] FILE
  origin PATH                               where an effective field comes from
  validate [-local|-sources|-overlay] FILE                    check a document, no side effects
  plan [-local|-sources|-overlay] FILE                        show what committing FILE changes
  commit [-local|-sources|-overlay] FILE [-base N] [-op ID] [-m MSG] [-yes]
  set [-local|-sources|-overlay] PATH JSON [-base N]          change one field, e.g. set /log/level '"debug"'
  remove [-local|-sources|-overlay] PATH [-base N]            remove a field or list element
  select GROUP MEMBER                       change a select group's choice
  revisions                                 list revisions
  restore REVISION [-yes]                   commit an old revision again
  op ID                                     result of an operation

runtime
  status
  group-status                               observed automatic choices and health
  explain DESTINATION [-network tcp|udp] [-source ADDR] [-addr IP]... [-resolve] [-process NAME]
  connections
  close ID...|all
  watch                                     stream events

secrets
  secret set NAME      (value from stdin)
  secret rm NAME
  secret ls
`

var (
	addrFlag  = flag.String("c", "", "control API address")
	rootFlag  = flag.String("state-root", "", "state root of the kernel (to find its default address)")
	jsonFlag  = flag.Bool("json", false, "print raw JSON results")
	client    *api.Client
	exitError = errors.New("")
)

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Args()); err != nil {
		if err != exitError {
			fmt.Fprintln(os.Stderr, "rekactl:", err)
		}
		os.Exit(1)
	}
}

func address() (string, error) {
	if *addrFlag != "" {
		return *addrFlag, nil
	}
	if v := os.Getenv("REKA_CONTROL"); v != "" {
		return v, nil
	}
	root := *rootFlag
	if root == "" {
		var err error
		if root, err = platform.DefaultStateRoot(); err != nil {
			return "", err
		}
	}
	return api.DefaultAddress(root), nil
}

func connect() error {
	addr, err := address()
	if err != nil {
		return err
	}
	c, err := api.Connect(addr, "rekactl")
	if err != nil {
		return fmt.Errorf("connect to %s: %w (is reka running?)", addr, err)
	}
	client = c
	return nil
}

func call(method string, params, out any) error {
	var raw json.RawMessage
	if err := client.Call(method, params, &raw); err != nil {
		return err
	}
	if *jsonFlag {
		var v any
		json.Unmarshal(raw, &v)
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func run(args []string) error {
	if err := connect(); err != nil {
		return err
	}
	defer client.Close()
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "get":
		return cmdGet(rest)
	case "subscription":
		return cmdSubscription(rest)
	case "import":
		return cmdImport(rest)
	case "origin":
		return cmdOrigin(rest)
	case "validate":
		return cmdValidate(rest)
	case "plan":
		return cmdPlan(rest)
	case "commit":
		return cmdCommit(rest)
	case "set", "remove":
		return cmdPatch(cmd, rest)
	case "select":
		if len(rest) != 2 {
			return errors.New("usage: select GROUP MEMBER")
		}
		return cmdSelect(rest[0], rest[1])
	case "revisions":
		return cmdRevisions()
	case "restore":
		return cmdRestore(rest)
	case "op":
		if len(rest) != 1 {
			return errors.New("usage: op ID")
		}
		var res api.Result
		if err := call("GetOperation", map[string]string{"operation_id": rest[0]}, &res); err != nil {
			return err
		}
		return printResult(res)
	case "group-status":
		var states []struct{ ID, Type, Selected string }
		if err := call("GetGroupStatus", nil, &states); err != nil {
			return err
		}
		if !*jsonFlag {
			for _, s := range states {
				fmt.Printf("%s (%s): %s\n", s.ID, s.Type, s.Selected)
			}
		}
		return nil
	case "status":
		return cmdStatus()
	case "explain":
		return cmdExplain(rest)
	case "connections":
		return cmdConnections()
	case "close":
		return cmdClose(rest)
	case "watch":
		return cmdWatch()
	case "secret":
		return cmdSecret(rest)
	}
	flag.Usage()
	return exitError
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	reveal := fs.Bool("reveal", false, "show inline credentials")
	what := "profile"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		what, args = args[0], args[1:]
	}
	parse(fs, args)
	var cfg api.Configuration
	if err := call("GetConfiguration", map[string]bool{"reveal": *reveal}, &cfg); err != nil {
		return err
	}
	if *jsonFlag {
		return nil
	}
	fmt.Fprintf(os.Stderr, "# revision %d\n", cfg.Revision)
	switch what {
	case "profile":
		fmt.Print(cfg.Profile)
	case "local":
		fmt.Print(cfg.Local)
	case "sources":
		fmt.Print(cfg.Sources)
	case "overlay":
		fmt.Print(cfg.Overlay)
	case "effective":
		b, _ := json.MarshalIndent(cfg.Effective, "", "  ")
		fmt.Println(string(b))
	default:
		return fmt.Errorf("get: unknown document %q", what)
	}
	for _, d := range cfg.Diagnostics {
		fmt.Fprintln(os.Stderr, d)
	}
	if cfg.StartError != "" {
		fmt.Fprintln(os.Stderr, "not running:", cfg.StartError)
	}
	return nil
}

func cmdOrigin(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: origin PATH")
	}
	var cfg api.Configuration
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil {
		return err
	}
	if cfg.Effective == nil {
		return errors.New("no effective configuration")
	}
	o, ok := cfg.Effective.OriginOf(args[0])
	if !ok {
		return fmt.Errorf("%s is not set", args[0])
	}
	if *jsonFlag {
		return json.NewEncoder(os.Stdout).Encode(o)
	}
	fmt.Printf("%s: %s", args[0], o.Layer)
	if o.Source != "" {
		fmt.Printf(" %s", o.Source)
	}
	if o.Document != "" {
		fmt.Printf(" %s%s", o.Document, o.Path)
	}
	if o.Line > 0 {
		fmt.Printf(" (line %d, column %d)", o.Line, o.Column)
	}
	if o.Overrides != nil {
		fmt.Printf(", overriding %s", o.Overrides.Layer)
		if o.Overrides.Line > 0 {
			fmt.Printf(" line %d", o.Overrides.Line)
		}
	}
	fmt.Println()
	return nil
}

// docFlags parses [-local|-sources|-overlay] FILE plus extra flags.
func docFlags(name string, args []string, extra func(*flag.FlagSet)) (document string, text string, fs *flag.FlagSet, err error) {
	fs = flag.NewFlagSet(name, flag.ExitOnError)
	l := fs.Bool("local", false, "local settings")
	s := fs.Bool("sources", false, "normalized sources")
	o := fs.Bool("overlay", false, "overlay")
	if extra != nil {
		extra(fs)
	}
	parse(fs, args)
	if fs.NArg() != 1 {
		return "", "", fs, fmt.Errorf("usage: %s [-local|-sources|-overlay] FILE", name)
	}
	var b []byte
	if fs.Arg(0) == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(fs.Arg(0))
	}
	document = "profile"
	count := 0
	for _, opt := range []struct {
		enabled bool
		name    string
	}{{*l, "local"}, {*s, "sources"}, {*o, "overlay"}} {
		if opt.enabled {
			document = opt.name
			count++
		}
	}
	if count > 1 {
		return "", "", fs, errors.New("choose one document flag")
	}
	return document, string(b), fs, err
}

func change(document string, text string, base uint64) api.ChangeRequest {
	req := api.ChangeRequest{BaseRevision: base}
	switch document {
	case "local":
		req.Local = &text
	case "sources":
		req.Sources = &text
	case "overlay":
		req.Overlay = &text
	default:
		req.Profile = &text
	}
	return req
}

func activeRevision() (uint64, error) {
	var cfg api.Configuration
	err := client.Call("GetConfiguration", nil, &cfg)
	return cfg.Revision, err
}

func printDiagnostics(ds model.Diagnostics) {
	for _, d := range ds {
		fmt.Fprintln(os.Stderr, d)
	}
}

func cmdValidate(args []string) error {
	local, text, _, err := docFlags("validate", args, nil)
	if err != nil {
		return err
	}
	var res api.ValidateResult
	if err := call("ValidateConfiguration", change(local, text, 0), &res); err != nil {
		return err
	}
	if *jsonFlag {
		return nil
	}
	printDiagnostics(res.Diagnostics)
	if !res.Valid {
		return exitError
	}
	fmt.Println("valid")
	return nil
}

func printPlan(p *api.Plan) {
	if p.NetworkChanged {
		fmt.Println("Network takeover:", p.NetworkNote)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, o := range p.Outbounds {
		if o.Action == api.ActionKeep {
			continue
		}
		fmt.Fprintf(w, "outbound %s\t%s", o.ID, o.Action)
		if o.Connections > 0 {
			fmt.Fprintf(w, "\t%d connections keep the old instance until they end", o.Connections)
		}
		fmt.Fprintln(w)
	}
	for _, l := range p.Listeners {
		if l.Action == api.ActionKeep {
			continue
		}
		fmt.Fprintf(w, "listener %s\t%s\t%s\t%s\n", l.ID, l.Action, l.Listen, l.Note)
	}
	for _, g := range p.Groups {
		fmt.Fprintf(w, "group %s\tselect\t%s -> %s\n", g.ID, g.From, g.To)
	}
	if p.DNSChanged {
		fmt.Fprintln(w, "DNS\tnew queries use the new resolver; existing fake mappings drain")
	}
	if p.AutomaticGroupsChanged {
		fmt.Fprintln(w, "automatic groups\thealth policy changes; manual selections are preserved")
	}
	if p.RulesChanged {
		fmt.Fprintf(w, "rules\treplace\t%d rules\n", p.Rules)
	}
	if p.LogLevel != "" {
		fmt.Fprintf(w, "log level\t%s\n", p.LogLevel)
	}
	for _, r := range p.RestartRequired {
		fmt.Fprintf(w, "%s\tneeds a restart\n", r)
	}
	if p.Blocked != "" {
		fmt.Fprintf(w, "blocked\t%s\n", p.Blocked)
	}
	w.Flush()
}

func cmdPlan(args []string) error {
	var base uint64
	local, text, _, err := docFlags("plan", args, func(fs *flag.FlagSet) { fs.Uint64Var(&base, "base", 0, "base revision (default: active)") })
	if err != nil {
		return err
	}
	if base == 0 {
		if base, err = activeRevision(); err != nil {
			return err
		}
	}
	var res api.PlanResult
	if err := call("PlanConfiguration", change(local, text, base), &res); err != nil {
		return err
	}
	if *jsonFlag {
		return nil
	}
	printDiagnostics(res.Diagnostics)
	if res.Conflict != nil {
		printConflict(res.Conflict)
		return exitError
	}
	if !res.Valid {
		return exitError
	}
	fmt.Printf("plan against revision %d (hash %s):\n", res.Base, res.PlanHash)
	printPlan(res.Plan)
	return nil
}

func printConflict(c *api.Conflict) {
	fmt.Fprintf(os.Stderr, "conflict: revision %d is active, the change was based on %d. Changed since:\n", c.Active, c.Base)
	for _, ch := range c.Changes {
		fmt.Fprintf(os.Stderr, "  %s: %v -> %v\n", ch.Path, ch.From, ch.To)
	}
}

func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line)) == "y"
}

func printResult(res api.Result) error {
	if *jsonFlag {
		if res.State != store.OpCommitted {
			return exitError
		}
		return nil
	}
	printDiagnostics(res.Diagnostics)
	if res.Conflict != nil {
		printConflict(res.Conflict)
	}
	switch res.State {
	case store.OpCommitted:
		if res.NoChange {
			fmt.Printf("no change; revision %d stays active (operation %s)\n", res.Revision, res.OperationID)
		} else {
			fmt.Printf("revision %d active, generation %d (operation %s)\n", res.Revision, res.Generation, res.OperationID)
		}
		return nil
	case store.OpPending:
		fmt.Printf("operation %s is still pending\n", res.OperationID)
		return nil
	}
	msg := res.State
	if res.Error != nil {
		msg += ": " + res.Error.Message
	}
	if res.Degraded {
		msg += " (degraded: some listeners could not be restored)"
	}
	fmt.Fprintln(os.Stderr, msg)
	return exitError
}

func commitWithPlan(req api.ChangeRequest, op, msg, source string, yes bool) error {
	var plan api.PlanResult
	if err := client.Call("PlanConfiguration", req, &plan); err != nil {
		return err
	}
	if plan.Conflict != nil {
		printConflict(plan.Conflict)
		return exitError
	}
	if !plan.Valid {
		printDiagnostics(plan.Diagnostics)
		return exitError
	}
	if !*jsonFlag {
		printPlan(plan.Plan)
		if plan.Plan.Interrupts && !yes && !confirm("This change briefly interrupts a listener. Commit?") {
			return exitError
		}
	}
	var res api.Result
	if err := call("CommitConfiguration", api.CommitRequest{ChangeRequest: req, OperationID: op, PlanHash: plan.PlanHash, Message: msg, Source: source}, &res); err != nil {
		return err
	}
	return printResult(res)
}

func cmdCommit(args []string) error {
	var (
		base    uint64
		op, msg string
		yes     bool
	)
	local, text, _, err := docFlags("commit", args, func(fs *flag.FlagSet) {
		fs.Uint64Var(&base, "base", 0, "revision the file was edited from (default: active, without conflict check)")
		fs.StringVar(&op, "op", "", "operation ID, for safe retries")
		fs.StringVar(&msg, "m", "", "message recorded with the revision")
		fs.BoolVar(&yes, "yes", false, "do not ask before interrupting a listener")
	})
	if err != nil {
		return err
	}
	if base == 0 {
		if base, err = activeRevision(); err != nil {
			return err
		}
	}
	return commitWithPlan(change(local, text, base), op, msg, "cli", yes)
}

func cmdPatch(op string, args []string) error {
	fs := flag.NewFlagSet(op, flag.ExitOnError)
	local := fs.Bool("local", false, "edit local settings")
	sources := fs.Bool("sources", false, "edit normalized sources")
	overlay := fs.Bool("overlay", false, "edit overlay")
	base := fs.Uint64("base", 0, "base revision (default: active)")
	yes := fs.Bool("yes", false, "do not ask before interrupting a listener")
	parse(fs, args)
	want := 2
	if op == "remove" {
		want = 1
	}
	if fs.NArg() != want {
		return fmt.Errorf("usage: %s [-local] PATH%s", op, map[bool]string{true: " JSON"}[op == "set"])
	}
	o := model.Op{Op: op, Path: fs.Arg(0)}
	if op == "set" {
		v := fs.Arg(1)
		if !json.Valid([]byte(v)) {
			// Bare words are strings.
			b, _ := json.Marshal(v)
			v = string(b)
		}
		o.Value = json.RawMessage(v)
	}
	b := *base
	if b == 0 {
		var err error
		if b, err = activeRevision(); err != nil {
			return err
		}
	}
	req := api.ChangeRequest{BaseRevision: b}
	count := 0
	for _, selected := range []bool{*local, *sources, *overlay} {
		if selected {
			count++
		}
	}
	if count > 1 {
		return errors.New("choose one document flag")
	}
	if *sources {
		req.SourcesPatch = []model.Op{o}
	} else if *overlay {
		req.OverlayPatch = []model.Op{o}
	} else if *local {
		req.LocalPatch = []model.Op{o}
	} else {
		req.Patch = []model.Op{o}
	}
	return commitWithPlan(req, "", "", "cli", *yes)
}

func cmdSelect(group, member string) error {
	value, _ := json.Marshal(member)
	path := model.JoinPath("/groups", group, "selected")
	if !strings.Contains(group, "/") {
		return cmdPatch("set", []string{path, string(value)})
	}
	var cfg api.Configuration
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil {
		return err
	}
	overlay, _, diags := model.ParseOverlay([]byte(cfg.Overlay))
	if diags.HasErrors() {
		return diags.Errors()
	}
	patch := model.Op{Op: "set", Path: path, Value: value}
	encoded, _ := json.Marshal(patch)
	edit := model.Op{Op: "insert", Path: "/patches", Value: encoded}
	for i, p := range overlay.Patches {
		if p.Op == "set" && p.Path == path {
			edit = model.Op{Op: "set", Path: fmt.Sprintf("/patches/#%d/value", i), Value: value}
		}
	}
	return commitWithPlan(api.ChangeRequest{BaseRevision: cfg.Revision, OverlayPatch: []model.Op{edit}}, "", "", "cli", false)
}

func cmdRevisions() error {
	var out struct {
		Active    uint64           `json:"active"`
		Revisions []store.Revision `json:"revisions"`
	}
	if err := call("ListRevisions", nil, &out); err != nil || *jsonFlag {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "REVISION\tCREATED\tSOURCE\tBASE\tMESSAGE")
	for _, r := range out.Revisions {
		mark := " "
		if r.Number == out.Active {
			mark = "*"
		}
		fmt.Fprintf(w, "%s%d\t%s\t%s\t%d\t%s\n", mark, r.Number, r.Created.Local().Format(time.DateTime), r.Source, r.Base, r.Message)
	}
	return w.Flush()
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask")
	parse(fs, args)
	if fs.NArg() != 1 {
		return errors.New("usage: restore REVISION")
	}
	n, err := strconv.ParseUint(fs.Arg(0), 10, 64)
	if err != nil {
		return err
	}
	base, err := activeRevision()
	if err != nil {
		return err
	}
	if !*yes && !*jsonFlag && !confirm(fmt.Sprintf("Commit revision %d again as a new revision (active is %d)?", n, base)) {
		return exitError
	}
	var res api.Result
	if err := call("RestoreRevision", api.RestoreRequest{Revision: n, BaseRevision: base}, &res); err != nil {
		return err
	}
	return printResult(res)
}

func cmdStatus() error {
	var st api.Status
	if err := call("GetStatus", nil, &st); err != nil || *jsonFlag {
		return err
	}
	fmt.Printf("revision %d, generation %d, %d connections, %d instances draining\n",
		st.Revision, st.Runtime.Generation, st.Runtime.Connections, st.Runtime.Draining)
	for _, l := range st.Runtime.Listeners {
		fmt.Printf("listener %s  %s  %s\n", l.ID, l.Action, l.Listen)
	}
	fmt.Printf("outbounds: %s\n", strings.Join(st.Runtime.Outbounds, ", "))
	if st.StartError != "" {
		fmt.Println("not running:", st.StartError)
	}
	return nil
}

// parse parses flags anywhere among the arguments ("commit FILE -m x").
func parse(fs *flag.FlagSet, args []string) {
	var pos []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	fs.Parse(pos)
}

type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	network := fs.String("network", "tcp", "tcp or udp")
	source := fs.String("source", "", "source address:port")
	resolve := fs.Bool("resolve", false, "allow a DNS lookup for ip rules")
	process := fs.String("process", "", "process executable name or full path to assume")
	inbound := fs.String("inbound", "", "inbound stable ID to assume")
	inboundType := fs.String("in-type", "", "actual inbound protocol to assume, for example SOCKS5")
	inboundUser := fs.String("in-user", "", "authenticated inbound user to assume")
	inboundPort := fs.Int("in-port", 0, "inbound listening port to assume")
	uid := fs.Int64("uid", -1, "owning UID to assume (-1 is unknown)")
	var addrs multi
	fs.Var(&addrs, "addr", "destination address to assume for ip rules (repeatable)")
	parse(fs, args)
	if fs.NArg() != 1 {
		return errors.New("usage: explain HOST:PORT [flags]")
	}
	req := api.ExplainRequest{Destination: fs.Arg(0), Network: *network, Source: *source, Resolve: *resolve, Addresses: addrs, Process: *process}
	if *inboundPort < 0 || *inboundPort > 65535 || *uid < -1 || *uid > 4294967295 {
		return errors.New("invalid inbound port or UID")
	}
	req.Inbound, req.InboundType, req.InboundUser, req.InboundPort = *inbound, *inboundType, *inboundUser, uint16(*inboundPort)
	if *uid >= 0 {
		value := uint32(*uid)
		req.ProcessUID = &value
	}
	var x api.Explanation
	if err := call("ExplainRoute", req, &x); err != nil || *jsonFlag {
		return err
	}
	if x.Undetermined != "" {
		fmt.Println("undetermined:", x.Undetermined)
		return nil
	}
	if x.Matched {
		id := ""
		if x.RuleID != "" {
			id = " (" + x.RuleID + ")"
		}
		fmt.Printf("rule %d%s: %s\n", x.RuleIndex, id, x.Rule)
	} else {
		fmt.Println("no rule matched; using the final target")
	}
	if len(x.Resolved) > 0 {
		fmt.Printf("resolved: %s\n", strings.Join(x.Resolved, ", "))
	}
	if x.ResolveError != "" {
		fmt.Printf("resolve failed: %s (ip rules did not match)\n", x.ResolveError)
	}
	path := append(append([]string{}, x.Chain...), x.Outbound)
	fmt.Printf("outbound: %s (%s, instance %s)\n", strings.Join(path, " -> "), x.OutboundType, x.Fingerprint)
	return nil
}

func cmdConnections() error {
	var out struct {
		Total       int              `json:"total"`
		Connections []api.Connection `json:"connections"`
	}
	if err := call("ListConnections", map[string]int{"limit": 1000}, &out); err != nil || *jsonFlag {
		return err
	}
	sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].ID < out.Connections[j].ID })
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNET\tDESTINATION\tOUTBOUND\tRULE\tGEN\tUP\tDOWN\tAGE")
	for _, c := range out.Connections {
		rule := c.RuleID
		if rule == "" {
			rule = c.Rule
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", c.ID, c.Network, c.Destination, c.Outbound, rule,
			c.Generation, c.Upload, c.Download, time.Since(c.Start).Round(time.Second))
	}
	return w.Flush()
}

func cmdClose(args []string) error {
	params := map[string]any{}
	if len(args) == 1 && args[0] == "all" {
		params["all"] = true
	} else {
		var ids []uint64
		for _, a := range args {
			n, err := strconv.ParseUint(a, 10, 64)
			if err != nil {
				return fmt.Errorf("close: %q is not a connection ID", a)
			}
			ids = append(ids, n)
		}
		params["ids"] = ids
	}
	var out struct{ Closed int }
	if err := call("CloseConnections", params, &out); err != nil || *jsonFlag {
		return err
	}
	fmt.Printf("closed %d connections\n", out.Closed)
	return nil
}

func cmdWatch() error {
	if err := client.Call("Subscribe", map[string]any{}, nil); err != nil {
		return err
	}
	for ev := range client.Events {
		b, _ := json.Marshal(ev.Data)
		drop := ""
		if ev.Dropped > 0 {
			drop = fmt.Sprintf(" (missed %d)", ev.Dropped)
		}
		fmt.Printf("%s #%d %s%s %s\n", ev.Time.Local().Format(time.TimeOnly), ev.Seq, ev.Type, drop, b)
	}
	return errors.New("connection closed")
}

func cmdSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: secret set|rm|ls")
	}
	switch args[0] {
	case "ls":
		var out struct{ Names []string }
		if err := call("ListSecrets", nil, &out); err != nil || *jsonFlag {
			return err
		}
		for _, n := range out.Names {
			fmt.Println(n)
		}
		return nil
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: secret rm NAME")
		}
		return call("DeleteSecret", map[string]string{"name": args[1]}, nil)
	case "set":
		if len(args) != 2 {
			return errors.New("usage: secret set NAME < value")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		value := strings.TrimRight(string(b), "\r\n")
		var out struct {
			Ref   string      `json:"ref"`
			Apply *api.Result `json:"apply"`
		}
		if err := call("SetSecret", map[string]string{"name": args[1], "value": value}, &out); err != nil || *jsonFlag {
			return err
		}
		fmt.Printf("stored; reference it as %s\n", out.Ref)
		if out.Apply != nil {
			return printResult(*out.Apply)
		}
		return nil
	}
	return fmt.Errorf("secret: unknown command %q", args[0])
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	id := fs.String("source", "", "stable source ID")
	format := fs.String("format", "auto", "auto, clash or links")
	nodesOnly := fs.Bool("nodes-only", false, "explicitly import only proxy nodes")
	partial := fs.Bool("allow-partial", false, "allow omissions after reviewing their diagnostics")
	apply := fs.Bool("apply", false, "plan and commit the imported source")
	attachments := map[string]string{}
	fs.Func("certificate-file", "explicit TLS attachment FOREIGN_PATH=LOCAL_FILE (repeatable)", func(value string) error {
		name, path, ok := strings.Cut(value, "=")
		if !ok || name == "" || path == "" || len(attachments) >= 64 {
			return errors.New("expected FOREIGN_PATH=LOCAL_FILE, at most 64 attachments")
		}
		if _, duplicate := attachments[name]; duplicate {
			return errors.New("duplicate certificate attachment")
		}
		f, err := os.Open(path)
		if err != nil {
			return errors.New("cannot open explicitly attached certificate file")
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(data) > 1<<20 {
			return errors.New("certificate attachment exceeds 1 MiB or could not be read")
		}
		attachments[name] = string(data)
		return nil
	})
	parse(fs, args)
	if *id == "" || fs.NArg() != 1 {
		return errors.New("usage: import -source ID [-nodes-only] [-allow-partial] [-apply] FILE")
	}
	var data []byte
	var err error
	if fs.Arg(0) == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, model.MaxDocumentSize+1))
	} else {
		f, e := os.Open(fs.Arg(0))
		if e != nil {
			return e
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, model.MaxDocumentSize+1))
	}
	if err != nil {
		return err
	}
	request := importer.Request{SourceID: *id, Format: *format, Data: string(data), NodesOnly: *nodesOnly, AllowPartial: *partial, CertificateFiles: attachments}
	var preview importer.Preview
	if err := call("ImportSource", map[string]any{"import": request}, &preview); err != nil {
		return err
	}
	if !*jsonFlag {
		printDiagnostics(preview.Report.Diagnostics)
		r := preview.Report
		fmt.Printf("source %s (%s): nodes %d/%d, groups %d/%d, rules %d/%d; can apply: %t\n", r.SourceID, r.Format, r.Nodes.Imported, r.Nodes.Total, r.Groups.Imported, r.Groups.Total, r.Rules.Imported, r.Rules.Total, r.CanApply)
	}
	if !preview.Report.CanApply {
		return exitError
	}
	if !*apply {
		return nil
	}
	base, err := activeRevision()
	if err != nil {
		return err
	}
	return commitWithPlan(api.ChangeRequest{BaseRevision: base, Import: &request}, "", "import source "+*id, "import", false)
}

func cmdSubscription(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: subscription list|set|refresh|pause|resume|remove")
	}
	action := args[0]
	if action == "list" {
		var statuses []api.SubscriptionStatus
		if err := call("ListSubscriptions", nil, &statuses); err != nil {
			return err
		}
		if !*jsonFlag {
			for _, status := range statuses {
				fmt.Printf("%s: %s (%s)\n", status.SourceID, status.State, status.ErrorCode)
			}
		}
		return nil
	}
	if action == "refresh" {
		if len(args) != 2 {
			return errors.New("usage: subscription refresh ID")
		}
		var status api.SubscriptionStatus
		if err := call("RefreshSubscription", map[string]any{"source_id": args[1], "wait": true}, &status); err != nil {
			return err
		}
		if !*jsonFlag {
			fmt.Printf("%s: %s (%s)\n", status.SourceID, status.State, status.ErrorCode)
		}
		if status.State != "current" {
			return exitError
		}
		return nil
	}
	fs := flag.NewFlagSet("subscription", flag.ExitOnError)
	interval := fs.Int("interval", 3600, "refresh interval in seconds (at least 30)")
	format := fs.String("format", "auto", "auto, clash or links")
	nodes := fs.Bool("nodes-only", false, "only nodes, including declared proxy providers")
	partial := fs.Bool("allow-partial", false, "explicitly accept supported subset")
	providerDirectory := fs.String("provider-directory", "", "explicit local directory for file providers")
	geoip := fs.String("geoip", "", "explicit GeoIP protobuf .dat URL or secret reference")
	geosite := fs.String("geosite", "", "explicit GeoSite protobuf .dat URL or secret reference")
	parse(fs, args[1:])
	want := 1
	if action == "set" {
		want = 2
	}
	if fs.NArg() != want {
		return errors.New("usage: subscription set ID URL [-interval N] [-nodes-only] or pause|resume|remove ID")
	}
	var cfg api.Configuration
	// Definition edits must round-trip masked URL/header values without
	// displaying them. ConfigService restores those masks from stored fields.
	if err := client.Call("GetConfiguration", nil, &cfg); err != nil {
		return err
	}
	var spec *model.Subscription
	switch action {
	case "set":
		spec = &model.Subscription{ProviderDirectory: *providerDirectory, URL: fs.Arg(1), Interval: *interval, Format: *format, NodesOnly: *nodes, AllowPartial: *partial}
		if *geoip != "" {
			spec.Geodata = append(spec.Geodata, model.GeoAsset{ID: "geoip", URL: *geoip})
		}
		if *geosite != "" {
			spec.Geodata = append(spec.Geodata, model.GeoAsset{ID: "geosite", URL: *geosite})
		}
	case "remove":
	case "pause", "resume":
		sources, _, ds := model.ParseSources([]byte(cfg.Sources))
		if ds.HasErrors() {
			return ds.Errors()
		}
		for _, src := range sources.Sources {
			if src.ID == fs.Arg(0) {
				spec = src.Subscription
			}
		}
		if spec == nil {
			return errors.New("subscription not found")
		}
		spec.Paused = action == "pause"
	default:
		return errors.New("unknown subscription action")
	}
	var result api.Result
	if err := call("ConfigureSubscription", map[string]any{"source_id": fs.Arg(0), "base_revision": cfg.Revision, "subscription": spec}, &result); err != nil {
		return err
	}
	return printResult(result)
}
