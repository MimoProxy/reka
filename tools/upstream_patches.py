"""Small source-hashed corrections for the locked component family.

The original module copies stay byte-identical. Only generated overlay files
change, and the corresponding-source package includes this generator.
"""


def replace(source, old, new, count=1):
    if source.count(old) != count:
        raise RuntimeError('Pinned patch context changed: ' + old[:90])
    return source.replace(old, new)


def vision(source):
    source = source.replace('reflectPointer uintptr', 'reflectPointer unsafe.Pointer')
    source = replace(source, 'uintptr(unsafe.Pointer(tlsConn))', 'unsafe.Pointer(tlsConn)')
    source = replace(source, 'unsafe.Pointer(reflectPointer + input.Offset)', 'unsafe.Add(reflectPointer, input.Offset)')
    source = replace(source, 'unsafe.Pointer(reflectPointer + rawInput.Offset)', 'unsafe.Add(reflectPointer, rawInput.Offset)')
    source = replace(source, '\twriteAccess sync.Mutex', '\twriteAccess sync.Mutex\n\treadAccess sync.Mutex\n\tfilterAccess sync.Mutex')
    source = replace(source, 'func (c *VisionConn) Read(p []byte) (n int, err error) {', 'func (c *VisionConn) Read(p []byte) (n int, err error) {\n\tc.readAccess.Lock()\n\tdefer c.readAccess.Unlock()')
    source = replace(source, 'c.numberOfPacketToFilter > 0', 'c.shouldFilterTLS()', 4)
    source = replace(source, '\tif c.isPadding {\n', '\tisTLS, isTLS12orAbove, enableXTLS, packetsToFilter := c.tlsState()\n\tif c.isPadding {\n')
    source = replace(source, 'if c.isTLS && buffer.Len()', 'if isTLS && buffer.Len()')
    source = replace(source, 'if c.enableXTLS {', 'if enableXTLS {')
    source = replace(source, '!c.isTLS12orAbove && c.numberOfPacketToFilter <= 1', '!isTLS12orAbove && packetsToFilter <= 1')
    source = replace(source, 'func (c *VisionConn) filterTLS(buffers [][]byte) {', '''func (c *VisionConn) tlsState() (bool, bool, bool, int) {
	c.filterAccess.Lock()
	defer c.filterAccess.Unlock()
	return c.isTLS, c.isTLS12orAbove, c.enableXTLS, c.numberOfPacketToFilter
}

func (c *VisionConn) shouldFilterTLS() bool {
	_, _, _, packets := c.tlsState()
	return packets > 0
}

func (c *VisionConn) filterTLS(buffers [][]byte) {
	c.filterAccess.Lock()
	defer c.filterAccess.Unlock()
	if c.numberOfPacketToFilter <= 0 { return }''')
    source = replace(source, 'if contentLen < 900 && c.isTLS {', 'isTLS, _, _, _ := c.tlsState()\n\tif contentLen < 900 && isTLS {')
    source = replace(source, 'input, _ := reflectType.FieldByName("input")\n\trawInput, _ := reflectType.FieldByName("rawInput")', '''input, inputOK := reflectType.FieldByName("input")
	rawInput, rawOK := reflectType.FieldByName("rawInput")
	if !inputOK || !rawOK || input.Type != reflect.TypeOf(bytes.Reader{}) || rawInput.Type != reflect.TypeOf(bytes.Buffer{}) {
		return nil, E.New("vision: unsupported TLS buffer layout")
	}''')
    # Encrypted VLESS exposes typed decrypted buffers for Vision's transition.
    # Keep the existing reflected/guarded path for ordinary TLS, without
    # introducing an unsafe dependency on Reka's encryption struct layout.
    start = source.index('\tfor _, tlsCreator := range tlsRegistry {', source.index('func NewVisionConn'))
    end = source.index('\treturn &VisionConn{', start)
    source = source[:start] + '''
 var input *bytes.Reader
 var rawInput *bytes.Buffer
 if provider,ok:=tlsConn.(interface{VisionBuffers()(net.Conn,*bytes.Reader,*bytes.Buffer)});ok {
  netConn,input,rawInput=provider.VisionBuffers()
  if netConn==nil || input==nil || rawInput==nil{return nil,E.New("vision: invalid encrypted stream buffers")}
 } else {
  for _,tlsCreator:=range tlsRegistry {
   loaded,netConn,reflectType,reflectPointer=tlsCreator(tlsConn)
   if loaded{break}
  }
  if !loaded{return nil,E.New("vision: not a valid supported TLS connection: ",reflect.TypeOf(tlsConn))}
  inputField,inputOK:=reflectType.FieldByName("input")
  rawField,rawOK:=reflectType.FieldByName("rawInput")
  if !inputOK || !rawOK || inputField.Type!=reflect.TypeOf(bytes.Reader{}) || rawField.Type!=reflect.TypeOf(bytes.Buffer{}){return nil,E.New("vision: unsupported TLS buffer layout")}
  input=(*bytes.Reader)(unsafe.Add(reflectPointer,inputField.Offset))
  rawInput=(*bytes.Buffer)(unsafe.Add(reflectPointer,rawField.Offset))
 }
''' + source[end:]
    source = replace(source, '(*bytes.Reader)(unsafe.Add(reflectPointer, input.Offset))', 'input')
    source = replace(source, '(*bytes.Buffer)(unsafe.Add(reflectPointer, rawInput.Offset))', 'rawInput')
    return source


def vision_utls(source):
    source = replace(source, 'reflectPointer uintptr', 'reflectPointer unsafe.Pointer')
    source = replace(source, 'uintptr(unsafe.Pointer(uConn.Conn))', 'unsafe.Pointer(uConn.Conn)')
    return replace(source, 'uintptr(unsafe.Pointer(tlsConn))', 'unsafe.Pointer(tlsConn)')


def packet_mutex(source, name):
    source = replace(source, '"net"', '"net"\n\t"sync"')
    source = replace(source, '\tremoteAddr M.Socksaddr\n', '\tremoteAddr M.Socksaddr\n\tremoteAccess sync.RWMutex\n')
    source += '''
func (c *%s) setRemoteAddr(value M.Socksaddr) {
	c.remoteAccess.Lock()
	c.remoteAddr = value
	c.remoteAccess.Unlock()
}

func (c *%s) getRemoteAddr() M.Socksaddr {
	c.remoteAccess.RLock()
	defer c.remoteAccess.RUnlock()
	return c.remoteAddr
}
''' % (name, name)
    return source


def bind(source):
    source = packet_mutex(source, 'serverPacketConn')
    source = replace(source, 'c.remoteAddr = M.SocksaddrFromNet(addr)', 'c.setRemoteAddr(M.SocksaddrFromNet(addr))')
    source = replace(source, 'c.remoteAddr = destination', 'c.setRemoteAddr(destination)')
    source = replace(source, 'c.remoteAddr.UDPAddr()', 'c.getRemoteAddr().UDPAddr()')
    source = replace(source, 'WritePacket(buffer, c.remoteAddr)', 'WritePacket(buffer, c.getRemoteAddr())')
    return replace(source, 'func (c *serverPacketConn) RemoteAddr() net.Addr {\n\treturn c.remoteAddr\n}', 'func (c *serverPacketConn) RemoteAddr() net.Addr {\n\treturn c.getRemoteAddr()\n}')


def bind_wait(source):
    return replace(source, 'w.remoteAddr = destination', 'w.setRemoteAddr(destination)')


def associate(source):
    source = packet_mutex(source, 'AssociatePacketConn')
    source = replace(source, 'c.remoteAddr = destination', 'c.setRemoteAddr(destination)', 2)
    source = replace(source, 'c.WriteTo(b, c.remoteAddr)', 'c.WriteTo(b, c.getRemoteAddr())')
    return replace(source, 'c.remoteAddr.UDPAddr()', 'c.getRemoteAddr().UDPAddr()')


def associate_wait(source):
    return replace(source, 'w.conn.remoteAddr = destination', 'w.conn.setRemoteAddr(destination)')


MODULES = {
    'github.com/sagernet/sing-vmess': ('v0.2.9-0.20261019223527-a0c58542bd9d', {
        'vless/vision.go': ('2e3dd96b5f521b16692a175c4d994c2b0aae700a7a21758d21a2c434132cc014', vision),
        'vless/vision_utls.go': ('23747cbe4fb6887a20d32f23bd7d4768a12d8d6a2bc4165a50885e3351d35545', vision_utls),
    }),
    'github.com/sagernet/sing': ('v0.9.7-0.20261023115459-5dc452e537bf', {
        'common/bufio/bind.go': ('581bcc7042231a0d4e76da58372bde94ad59d59e460b6f84200b193976d4bc9e', bind),
        'common/bufio/bind_wait.go': ('ee1581ff0a07d1858f5edafc5c767e9cc884a2462cf350e55ffacfa65dd59203', bind_wait),
        'protocol/socks/packet.go': ('f4d9087108e299d46d7cf39f2a9acadc99b480df5b87c3c12132a01d8b72cb92', associate),
        'protocol/socks/packet_wait.go': ('8b576aa95aed88740abf840db5ed048b08f5a6e48190be4650e915442f041edd', associate_wait),
    }),
}


def tls_client_hook(source):
    return replace(source, '\tconfig.SetServerName(serverName)', '\tconfig.SetServerName(serverName)\n\tif configure, ok := ctx.Value("reka.tls.configure.v1").(func(any) error); ok {\n\t\tif err := configure(&tlsConfig); err != nil { return nil, err }\n\t}')

MODULES['github.com/sagernet/sing-box'] = ('v1.14.4', {
'common/tls/std_client.go': ('4c6cb5a32da14a8a338fc6ffef31aa1e5be0f8c3f6a6a0cf2587825f1a4557ea', tls_client_hook),
'common/tls/utls_client.go': ('9ee08ca9ee2ee992e6f0eefc579c8540958c35ada1bf048df71491448a018403', tls_client_hook),
})


def cached_buffers(source):
    import re
    source = replace(source, '"sync/atomic"', '"sync/atomic"\n"sync"')
    for name in ['CachedConn', 'CachedReader', 'CachedPacketConn']:
        source = replace(source, 'type ' + name + ' struct {', 'type ' + name + ' struct {\n access sync.Mutex')
    for name, receiver, method in [('CachedConn', 'c', 'ReadCached'), ('CachedReader', 'r', 'ReadCached'), ('CachedPacketConn', 'c', 'ReadCachedPacket')]:
        needle = 'func (' + receiver + ' *' + name + ') ' + method
        start = source.index(needle)
        body = source.index('{', start) + 1
        source = source[:body] + '\n' + receiver + '.access.Lock()\ndefer ' + receiver + '.access.Unlock()' + source[body:]
    def function(name, receiver, method, body):
        nonlocal source
        pattern = r'func \(' + receiver + r' \*' + name + r'\) ' + method + r'\([^\n]*\n.*?\n}'
        source, count = re.subn(pattern, lambda _: body, source, count=1, flags=re.S)
        if count != 1:
            raise SystemExit('cached buffer patch no longer matches ' + name + '.' + method)
    for name, receiver, upstream in [('CachedConn', 'c', 'c.Conn'), ('CachedReader', 'r', 'r.upstream')]:
        function(name, receiver, 'Read', '''func (X *TYPE) Read(p []byte) (n int, err error) {
 X.access.Lock()
 if X.buffer != nil {
  n, err = X.buffer.Read(p)
  if err == nil { X.access.Unlock(); return }
  X.buffer.DecRef(); X.buffer.Release(); X.buffer=nil
 }
 X.access.Unlock()
 return UPSTREAM.Read(p)
}'''.replace('TYPE', name).replace('UPSTREAM', upstream).replace('X', receiver))
        function(name, receiver, 'WriteTo', '''func (X *TYPE) WriteTo(w io.Writer) (n int64, err error) {
 X.access.Lock(); buffer:=X.buffer; X.buffer=nil; X.access.Unlock()
 if buffer!=nil {
  bufferLen:=buffer.Len(); wn,wErr:=w.Write(buffer.Bytes()); buffer.DecRef(); buffer.Release(); n=int64(wn)
  if wErr!=nil{return n,wErr}; if wn<bufferLen {return n,io.ErrShortWrite}
 }
 cn,err:=Copy(w,UPSTREAM);return n+cn,err
}'''.replace('TYPE', name).replace('UPSTREAM', upstream).replace('X', receiver))
    function('CachedPacketConn', 'c', 'ReadPacket', '''func (c *CachedPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
 c.access.Lock()
 if c.buffer!=nil {
  _,err=buffer.ReadOnceFrom(c.buffer)
  if err!=nil {c.access.Unlock();return M.Socksaddr{},err}
  c.buffer.DecRef();c.buffer.Release();c.buffer=nil
  destination=c.destination;c.access.Unlock();return destination,nil
 }
 c.access.Unlock();return c.PacketConn.ReadPacket(buffer)
}''')
    for name, receiver, upstream in [('CachedConn', 'c', 'c.Conn'), ('CachedReader', 'r', ''), ('CachedPacketConn', 'c', 'c.PacketConn')]:
        function(name, receiver, 'ReaderReplaceable', 'func (X *TYPE) ReaderReplaceable() bool {\nX.access.Lock();defer X.access.Unlock();return X.buffer==nil\n}'.replace('TYPE', name).replace('X', receiver))
        function(name, receiver, 'Close', '''func (X *TYPE) Close() error {
 var err error
 CLOSE
 X.access.Lock();defer X.access.Unlock()
 if X.taken.CompareAndSwap(false,true) && X.buffer!=nil {X.buffer.DecRef();X.buffer.Release();X.buffer=nil}
 return err
}'''.replace('TYPE', name).replace('CLOSE', 'err='+upstream+'.Close()' if upstream else '').replace('X', receiver))
    return source

MODULES['github.com/sagernet/sing'][1]['common/bufio/cache.go'] = ('0ecef13bca92ca3c5b6688471e3562e1010a5596193859537cdea517cdb1c3fb', cached_buffers)


def windows_tfo_fd(source):
    source = replace(source, '"time"', '"time"\n"reflect"\n"runtime"\n"strings"\n"errors"')
    source = replace(source, '//go:linkname newFD net.newFD\nfunc newFD(sysfd windows.Handle, family, sotype int, net string) (*netFD, error)', '''//go:linkname newFDInternal net.newFD
func newFDInternal(sysfd windows.Handle, family, sotype int, net string) *netFD

func newFD(sysfd windows.Handle, family, sotype int, network string) (*netFD,error) {
 if !strings.HasPrefix(runtime.Version(),"go1.27.") && runtime.Version()!="go1.27" {return nil,errors.New("TFO requires reviewed Go 1.27 Windows ABI")}
 tcp:=reflect.TypeFor[net.TCPConn]()
 conn,ok:=tcp.FieldByName("conn");if !ok{return nil,errors.New("unrecognized TCPConn layout")}
 descriptor,ok:=conn.Type.FieldByName("fd");if !ok || descriptor.Type.Kind()!=reflect.Pointer{return nil,errors.New("unrecognized netFD layout")}
 actual,expected:=descriptor.Type.Elem(),reflect.TypeFor[netFD]()
 if actual.Size()!=expected.Size(){return nil,errors.New("unrecognized netFD size")}
 for i:=0;i<expected.NumField();i++{field:=expected.Field(i);other,ok:=actual.FieldByName(field.Name);if !ok || other.Offset!=field.Offset || other.Type.Size()!=field.Type.Size(){return nil,errors.New("unrecognized netFD field layout")}}
 physical,_:=actual.FieldByName("pfd");ours:=reflect.TypeFor[pFD]()
 mutex,ok:=physical.Type.FieldByName("fdmu");if !ok || mutex.Offset!=0 || mutex.Type.Size()!=16{return nil,errors.New("unrecognized poll FD mutex layout")}
 for i:=3;i<ours.NumField();i++{field:=ours.Field(i);other,ok:=physical.Type.FieldByName(field.Name);if !ok || other.Offset!=field.Offset || other.Type.Size()!=field.Type.Size(){return nil,errors.New("unrecognized poll FD field layout")}}
 return newFDInternal(sysfd,family,sotype,network),nil
}''')
    return source


def windows_tfo_poll(source):
    source = replace(source, '\tZeroReadIsEOF bool', '\tZeroReadIsEOF bool\n\tKeepFileCompletionModes bool')
    source = replace(source, 'submit func(o *operation) (uint32, error), buf []byte)', 'submit func(o *operation) (uint32, error), pinPtrs ...any)')
    return replace(source, '}, b)', '}, unsafe.SliceData(b))')

MODULES['github.com/database64128/tfo-go/v2'] = ('v2.3.2', {
'netpoll_windows_checklinkname0.go': ('ac0367d3354c382761e264bd19aa5dc705a1421577b2a575c6ea76f224f348bd',windows_tfo_fd),
'netpoll_windows_go127_checklinkname0.go': ('612ccecc8e755a8330889f05c0b91092329848f54bc2c815d5c595e6c565326c',windows_tfo_poll),
})


def multipath_both_families(source):
    return replace(source, 'dialer4.SetMultipathTCP(true)', 'dialer4.SetMultipathTCP(true)\n\t\tdialer6.SetMultipathTCP(true)')

MODULES['github.com/sagernet/sing-box'][1]['common/dialer/default.go'] = ('69dd2b689d80c2ab1e8793eb19037c91eed91f2399f57b3829e510d49f50586d', multipath_both_families)


def shadowsocks2022_client(source):
    source = replace(source, '"context"', '"context"\n"errors"\n"sync"\n"sync/atomic"')
    source = replace(source, 'type clientConn struct {', 'type clientConn struct {\n readAccess sync.Mutex\n writeAccess sync.Mutex\n closeOnce sync.Once\n closeErr error')
    source = replace(source, 'requestSalt     []byte', 'requestSalt     atomic.Pointer[[]byte]')
    source = replace(source, '\t_, err = c.Conn.Write(requestBuffer.Bytes())', '\tc.requestSalt.Store(&requestSalt)\n\t_, err = c.Conn.Write(requestBuffer.Bytes())')
    source = replace(source, '\tc.requestSalt = requestSalt\n', '')
    source = replace(source, 'if !bytes.Equal(responseSalt, c.requestSalt) {', 'requestSalt:=c.requestSalt.Load()\n\tif requestSalt==nil || !bytes.Equal(responseSalt, *requestSalt) {')
    for signature in ['Read(p []byte) (n int, err error)', 'ReadBuffer(buffer *buf.Buffer) error']:
        source = replace(source, 'func (c *clientConn) ' + signature + ' {', 'func (c *clientConn) ' + signature + ' {\n c.readAccess.Lock();defer c.readAccess.Unlock()')
    for signature in ['Write(p []byte) (n int, err error)', 'WriteBuffer(buffer *buf.Buffer) error', 'NeedHandshake() bool']:
        source = replace(source, 'func (c *clientConn) ' + signature + ' {', 'func (c *clientConn) ' + signature + ' {\n c.writeAccess.Lock();defer c.writeAccess.Unlock()')
    return replace(source, '''func (c *clientConn) Close() error {
	return common.Close(
		c.Conn,
		common.PtrOrNil(c.reader),
		common.PtrOrNil(c.writer),
	)
}''', '''func (c *clientConn) Close() error {
 c.closeOnce.Do(func(){
  err:=c.Conn.Close()
  c.readAccess.Lock();defer c.readAccess.Unlock()
  c.writeAccess.Lock();defer c.writeAccess.Unlock()
  c.closeErr=errors.Join(err,common.Close(common.PtrOrNil(c.reader),common.PtrOrNil(c.writer)))
 })
 return c.closeErr
}''')


def shadowsocks2022_wait(source):
    for signature in ['InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool)', 'WaitReadBuffer() (buffer *buf.Buffer, err error)']:
        source = replace(source, 'func (c *clientConn) ' + signature + ' {', 'func (c *clientConn) ' + signature + ' {\n c.readAccess.Lock();defer c.readAccess.Unlock()')
    return source

MODULES['github.com/sagernet/sing-shadowsocks2'] = ('v0.2.2-0.20260929152114-a69d1086332b', {
'shadowaead_2022/method.go': ('c1000a3459014e4708cc5713133457924a1d795e651e5c1dac52038f675c7272',shadowsocks2022_client),
'shadowaead_2022/method_wait.go': ('f080b9f6da06c9349b28db37b00cf2ca687676b329077743fa2b2be455183804',shadowsocks2022_wait),
})


def shadowsocks2022_server(source):
    import re
    source = replace(source, '"context"', '"context"\n"errors"')
    source = replace(source, 'type serverConn struct {', 'type serverConn struct {\n readAccess sync.Mutex\n closeOnce sync.Once\n closeErr error')
    source = replace(source, 'func (c *serverConn) Read(b []byte) (n int, err error) {', 'func (c *serverConn) Read(b []byte) (n int, err error) {\n c.readAccess.Lock();defer c.readAccess.Unlock()')
    bodies = {
        'Write': '''func (c *serverConn) Write(p []byte) (n int, err error) {
 c.access.Lock();defer c.access.Unlock()
 if c.writer!=nil{return c.writer.Write(p)}
 return c.writeResponse(p)
}''',
        'WriteVectorised': '''func (c *serverConn) WriteVectorised(buffers []*buf.Buffer) error {
 c.access.Lock();defer c.access.Unlock()
 if c.writer!=nil{return c.writer.WriteVectorised(buffers)}
 if len(buffers)==0{return nil}
 _,err:=c.writeResponse(buffers[0].Bytes())
 if err!=nil{buf.ReleaseMulti(buffers);return err}
 buffers[0].Release();return c.writer.WriteVectorised(buffers[1:])
}''',
        'Close': '''func (c *serverConn) Close() error {
 c.closeOnce.Do(func(){
  err:=c.Conn.Close()
  c.readAccess.Lock();defer c.readAccess.Unlock()
  c.access.Lock();defer c.access.Unlock()
  c.closeErr=errors.Join(err,common.Close(common.PtrOrNil(c.reader),common.PtrOrNil(c.writer)))
 })
 return c.closeErr
}'''
    }
    for method, body in bodies.items():
        pattern = r'func \(c \*serverConn\) ' + method + r'\([^\n]*\n.*?\n}'
        source, count = re.subn(pattern, lambda _: body, source, count=1, flags=re.S)
        if count != 1:
            raise SystemExit('SS2022 server patch no longer matches ' + method)
    return source

MODULES['github.com/sagernet/sing-shadowsocks'] = ('v0.2.9-0.20260929204512-65740e0f0e3e', {
'shadowaead_2022/service.go': ('b3fbe6500639625a99f2c685253cae586c3ca2b30e484e0bb38a9c8acab1462d',shadowsocks2022_server),
})


def vless_encryption(source):
    source = replace(source, 'type Outbound struct {', 'type Outbound struct {\n rekaEncryption func(context.Context,net.Conn)(net.Conn,error)')
    source = replace(source, '\t\tserverAddr: options.ServerOptions.Build(),\n\t}', '''\t\tserverAddr: options.ServerOptions.Build(),
 }
 if hook,ok:=ctx.Value("reka.vless.encryption.v1").(func()func(context.Context,net.Conn)(net.Conn,error));ok{outbound.rekaEncryption=hook()}''')
    hook = '''
 if h.rekaEncryption!=nil {
  conn,err=h.rekaEncryption(ctx,conn)
  if err!=nil{return nil,err}
 }
'''
    source = replace(source, '\tswitch N.NetworkName(network) {\n\tcase N.NetworkTCP:', hook+'\tswitch N.NetworkName(network) {\n\tcase N.NetworkTCP:')
    source = replace(source, '\tif h.xudp {\n\t\treturn h.client.DialEarlyXUDPPacketConn(conn, destination)', hook+'\tif h.xudp {\n\t\treturn h.client.DialEarlyXUDPPacketConn(conn, destination)')
    return source

MODULES['github.com/sagernet/sing-box'][1]['protocol/vless/outbound.go'] = ('3dfaa4e1eb7df0cffd7c23b473caf4809f0b6ede516ef077c8dd1acdd1bc9561',vless_encryption)


def vless_test_decryption(source):
    return replace(source, '\terr := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)', '''
 if decrypt,ok:=h.ctx.Value("reka.vless.decrypt.v1").(func(context.Context,net.Conn)(net.Conn,error));ok {
  encrypted,err:=decrypt(ctx,conn)
  if err!=nil {N.CloseOnHandshakeFailure(conn,onClose,err);return}
  conn=encrypted
 }
 err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)''')

MODULES['github.com/sagernet/sing-box'][1]['protocol/vless/inbound.go'] = ('5d783df51e9e88cd94c30b4b49402ead55e2a162bc5d72d99d4e3b226fd6d499',vless_test_decryption)


def mux_request_headroom(source):
    import re
    source = replace(source, '"net"', '"net"\n"io"')
    methods = {
        'protocolConn': '''func (c *protocolConn) Write(p []byte) (n int, err error) {
 if c.requestWritten{return c.Conn.Write(p)}
 buffer:=EncodeRequest(c.request,p)
 prefix,total:=buffer.Len()-len(p),buffer.Len()
 written,err:=c.Conn.Write(buffer.Bytes())
 buffer.Release()
 c.requestWritten=true
 if err==nil && written!=total{err=io.ErrShortWrite}
 return max(0,min(len(p),written-prefix)),err
}''',
        'vectorisedProtocolConn': '''func (c *vectorisedProtocolConn) WriteVectorised(buffers []*buf.Buffer) error {
 if !c.requestWritten {
  c.requestWritten=true
  buffers=append([]*buf.Buffer{EncodeRequest(c.request,nil)},buffers...)
 }
 front,rear:=N.CalculateFrontHeadroom(c.Conn),N.CalculateRearHeadroom(c.Conn)
 for index,buffer:=range buffers {
  if buffer.Start()>=front && buffer.FreeLen()>=rear{continue}
  reserved:=buf.NewSize(front+buffer.Len()+rear)
  reserved.Resize(front,0)
  _,err:=reserved.Write(buffer.Bytes())
  if err!=nil{reserved.Release();buf.ReleaseMulti(buffers);return err}
  buffer.Release();buffers[index]=reserved
 }
 return c.writer.WriteVectorised(buffers)
}'''
    }
    for receiver, body in methods.items():
        method = 'Write' if receiver == 'protocolConn' else 'WriteVectorised'
        pattern = r'func \(c \*' + receiver + r'\) ' + method + r'\([^\n]*\n.*?\n}'
        source, count = re.subn(pattern, lambda _: body, source, count=1, flags=re.S)
        if count != 1:
            raise SystemExit('Mux protocol patch no longer matches ' + receiver)
    return source

MODULES['github.com/sagernet/sing-mux'] = ('v0.3.10-0.20260929204512-caf09fe32475', {
'protocol_conn.go': ('a85c5e2aad78458529c9ac8df24fcdef09ec7b9490ce2ee4da8b70c415936546',mux_request_headroom),
})


def vectorised_headroom(source):
    source = replace(source, 'func CreateVectorisedWriter(writer any) (N.VectorisedWriter, bool) {', '''func CreateVectorisedWriter(writer any) (result N.VectorisedWriter, ok bool) {
 defer func(){
  if ok && result!=nil && (N.CalculateFrontHeadroom(writer)>0 || N.CalculateRearHeadroom(writer)>0){
   result=&headroomVectorisedWriter{writer:result,upstream:writer}
  }
 }()''')
    source += '''
// Native vector writers may prepend a protocol header. Callers of the
// vector interface (including multiplex servers) need not allocate headroom.
type headroomVectorisedWriter struct {
 writer N.VectorisedWriter
 upstream any
}
func(w *headroomVectorisedWriter)Upstream()any{return w.upstream}
func(w *headroomVectorisedWriter)WriteVectorised(buffers []*buf.Buffer)error{
 front,rear:=N.CalculateFrontHeadroom(w.upstream),N.CalculateRearHeadroom(w.upstream)
 for index,buffer:=range buffers {
  if buffer.Start()>=front && buffer.FreeLen()>=rear{continue}
  reserved:=buf.NewSize(front+buffer.Len()+rear)
  reserved.Resize(front,0)
  _,err:=reserved.Write(buffer.Bytes())
  if err!=nil{reserved.Release();buf.ReleaseMulti(buffers);return err}
  buffer.Release();buffers[index]=reserved
 }
 return w.writer.WriteVectorised(buffers)
}
'''
    return source

MODULES['github.com/sagernet/sing'][1]['common/bufio/vectorised.go'] = ('23187e4124d69376593edbe8b5915cab72d7fc737cb71decfcec81b8a0cbc571',vectorised_headroom)


def snell_conn_headroom(source):
    import re
    pattern = r'(func \(c \*(?:clientConn|reuseConn|serverReuseConn\[U\])\) (?:FrontHeadroom|RearHeadroom)\(\) int \{)'
    source, count = re.subn(pattern, lambda m: m[0] + '\n c.access.Lock();defer c.access.Unlock()', source)
    if count == 0:
        raise SystemExit('Snell connection headroom patch no longer matches')
    return source


def snell_writer_headroom(source):
    import re
    pattern = r'(func \(w \*(?:writer|shapedWriter)\) FrontHeadroom\(\) int \{)'
    source, count = re.subn(pattern, lambda m: m[0] + '\n w.access.Lock();defer w.access.Unlock()', source)
    if count != 1:
        raise SystemExit('Snell writer headroom patch no longer matches')
    return source

MODULES['github.com/sagernet/sing-snell'] = ('v0.0.0-20260904135315-bc5a12ac736f', {
'snellv4/client.go': ('f61e960d13881bd47653070b0d15495dd5c1747006e8138c1ecbec279b95d616', snell_conn_headroom),
'snellv4/reuse.go': ('5f6ca8cd0902d65290e5f2d9504339688ae97c7cd4e990e2713c1fcd2337ee04', snell_conn_headroom),
'snellv4/record.go': ('9b3fdcda036a12ff4d0368c42d059af4e14deae818673766e570201dacaf9617', snell_writer_headroom),
'snellv5/reuse.go': ('61dcffdfe1b33f52540de19a1429510c40118b777eb000177c72b5e9f82ea692', snell_conn_headroom),
'snellv6/client.go': ('2c40c0d1b5a04f266fe7ac77f95588d802519d985c3d2841f388a257b26bcc6c', snell_conn_headroom),
'snellv6/reuse.go': ('dcd883d3bf647ee89b25251d9a6e8dab9d551850a14be522b2688dce84cc6c57', snell_conn_headroom),
'snellv6/shaped.go': ('5bb41523f7532559f37993309366fb9bdbc1b0ad81a874fc8fa5e18f9e3598c3', snell_writer_headroom),
})


def hysteria_response_serialization(source):
    source = replace(source, 'type serverConn struct {', 'type serverConn struct {\n writeAccess sync.Mutex')
    source = replace(source, 'func (c *serverConn) HandshakeFailure(err error) error {', '''func (c *serverConn) HandshakeFailure(err error) error {
 // An in-flight success/data write must not delay teardown on failure.
 if !c.writeAccess.TryLock(){return os.ErrInvalid}
 defer c.writeAccess.Unlock()''')
    for signature in ['HandshakeSuccess() error', 'Write(p []byte) (n int, err error)']:
        source = replace(source, 'func (c *serverConn) ' + signature + ' {', 'func (c *serverConn) ' + signature + ' {\n c.writeAccess.Lock();defer c.writeAccess.Unlock()')
    return source

MODULES['github.com/sagernet/sing-quic'] = ('v0.7.2-0.20261020082049-7e0a5869a5f4', {
'hysteria2/service.go': ('8a8720cd5dbd4c58f6372b6b103d38575150a831c3d724b5a0ff3640d6a98b14',hysteria_response_serialization),
})


def smux_frame_ownership(source):
    source = replace(source, '"encoding/binary"', '"encoding/binary"\n"bytes"')
    return replace(source, 'func (s *Session) writeFrameInternal(f Frame, deadline <-chan time.Time, class CLASSID) (int, error) {', '''func (s *Session) writeFrameInternal(f Frame, deadline <-chan time.Time, class CLASSID) (int, error) {
 // A deadline or session close can return before sendLoop consumes this
 // queued frame. The queue must own its payload beyond the caller's Write.
 f.data=bytes.Clone(f.data)''')

MODULES['github.com/sagernet/smux'] = ('v1.5.50-sing-box-mod.1', {
'session.go': ('b66f8161fa3e9a7614679d17904b4fb71107ec5baff49338ccf141ab684c8a19',smux_frame_ownership),
})
