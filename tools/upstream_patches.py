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


def hysteria_exact_bandwidth(source):
    source=replace(source,'client, err := hysteria2.NewClient(hysteria2.ClientOptions{','clientOptions:=hysteria2.ClientOptions{')
    return replace(source,'RealmOptions: realmOptions,\n\t})','''RealmOptions: realmOptions,
 }
 if override,ok:=ctx.Value("reka.hysteria.bandwidth.v1").(func(*uint64,*uint64));ok{override(&clientOptions.SendBPS,&clientOptions.ReceiveBPS)}
 client,err:=hysteria2.NewClient(clientOptions)''')

MODULES['github.com/sagernet/sing-box'][1]['protocol/hysteria2/outbound.go'] = ('25b9c083a39a7d47be9fac675a8672e68654179858f7589ae60398ece0c48d80',hysteria_exact_bandwidth)


def shadowtls_record_writes(source):
    import re
    receiver='shadowConn' if 'type shadowConn struct' in source else 'verifiedConn'
    if receiver=='shadowConn':
        source=replace(source,'"net"','"net"\n"sync"')
    source=replace(source,'type '+receiver+' struct {','type '+receiver+' struct {\n writeAccess sync.Mutex')
    source=replace(source,'func (c *'+receiver+') Write(p []byte) (n int, err error) {','func (c *'+receiver+') Write(p []byte) (n int, err error) {\n c.writeAccess.Lock();defer c.writeAccess.Unlock();return c.writeRecords(p)\n}\nfunc(c *'+receiver+')writeRecords(p []byte)(n int,err error){')
    if receiver=='verifiedConn':
        start=source.index('func (c *verifiedConn) Write(p []byte)')
        end=source.index('\nfunc (c *verifiedConn) write(',start)
        source=source[:start]+'''func(c *verifiedConn)Write(p []byte)(n int,err error){
 c.writeAccess.Lock();defer c.writeAccess.Unlock();return c.writeRecords(p)
}
func(c *verifiedConn)writeRecords(p []byte)(n int,err error){
 for len(p)>0{
  size:=len(p);if size>16384{size=16384}
  written,err:=c.write(p[:size]);n+=written
  if err!=nil{return n,err}
  if written!=size{return n,io.ErrShortWrite}
  p=p[size:]
 }
 return n,nil
}
'''+source[end:]
        pattern=r'func \(c \*verifiedConn\) WriteBuffer\(buffer \*buf.Buffer\) error \{.*?\n}'
        source,count=re.subn(pattern,'''func(c *verifiedConn)WriteBuffer(buffer *buf.Buffer)error{
 defer buffer.Release()
 _,err:=c.Write(buffer.Bytes());return err
}''',source,count=1,flags=re.S)
        if count!=1:raise SystemExit('ShadowTLS WriteBuffer context changed')
    pattern=r'func \(c \*'+receiver+r'\) WriteVectorised\(buffers \[\]\*buf.Buffer\) error \{.*?\n}'
    replacement='''func(c *'''+receiver+''')WriteVectorised(buffers []*buf.Buffer)error{
 // A vector can exceed the TLS record length. The ordinary writer already
 // splits records, maintains the correct rolling HMAC, and reports errors.
 // Hold the lock across the entire logical vector, including v2 authentication.
 c.writeAccess.Lock();defer c.writeAccess.Unlock()
 defer buf.ReleaseMulti(buffers)
 for _,buffer:=range buffers{
  written,err:=c.writeRecords(buffer.Bytes());if err!=nil{return err}
  if written!=buffer.Len(){return io.ErrShortWrite}
 }
 return nil
}'''
    source,count=re.subn(pattern,lambda _:replacement,source,count=1,flags=re.S)
    if count!=1:raise SystemExit('ShadowTLS vector context changed')
    return source

MODULES['github.com/sagernet/sing-shadowtls'] = ('v0.2.2-0.20260928201441-a9c0127d5c99', {
'v2_conn.go': ('1d56d9e5535a285c279003438bc26c60d3da958c8adfe6c61bb7747c97023406',shadowtls_record_writes),
'v3_conn.go': ('b2dbea8cf093dd133302c9d4afc6dd64d3bf42f0bf882a5a57c7bc43af14f3bf',shadowtls_record_writes),
})


def simple_obfs_eof(source):
    return replace(source,'_, err = io.ReadFull(to.Conn, sizeBuf)\n\tif err != nil {\n\t\treturn 0, nil','_, err = io.ReadFull(to.Conn, sizeBuf)\n\tif err != nil {\n\t\treturn 0, err')

MODULES['github.com/sagernet/sing-box'][1]['transport/simple-obfs/tls.go'] = ('5dc636d2b39e9992366488a46899defc8568e70dade5a2bdf9bea18f62b389b7',simple_obfs_eof)


def lazy_tls_publication(source):
    # Keep the embedded physical socket immutable: net/http may close it while
    # the first read is still completing the TLS handshake.
    source = replace(source, '"sync"', '"sync"\n"sync/atomic"')
    source = replace(source, 'needHandshake bool', 'tlsConn atomic.Pointer[Conn]')
    source = replace(source, '\n\t\tneedHandshake: true,', '')
    source = replace(source, 'if !c.needHandshake {', 'if c.tlsConn.Load() != nil {')
    source = replace(source, 'if c.needHandshake {', 'if c.tlsConn.Load() == nil {')
    source = replace(source, 'c.Conn = tlsConn\n\t\tc.needHandshake = false', 'c.tlsConn.Store(&tlsConn)')
    source = replace(source, 'return c.Conn.Read(p)', 'return (*c.tlsConn.Load()).Read(p)')
    source = replace(source, 'return c.Conn.Write(p)', 'return (*c.tlsConn.Load()).Write(p)')
    source = replace(source, 'return c.needHandshake', 'return c.tlsConn.Load() == nil')
    source = replace(source, 'return !c.needHandshake', 'return c.tlsConn.Load() != nil', 2)
    return replace(source, 'return c.Conn\n}', 'if conn := c.tlsConn.Load(); conn != nil { return *conn }; return c.Conn\n}')

MODULES['github.com/sagernet/sing'][1]['common/tls/listener.go'] = ('db3287682b4be62be1d1982acceb102a12bd10bf019bfe4c7a411bc952f581ba', lazy_tls_publication)


def h2_reservation_lock(source):
    # Backport golang/net 8d10596 (Go issue 80680), BSD-3-Clause. Reserve
    # synchronously invokes stateHook, so neither call may hold cc.mu.
    source = replace(source, 'err := func() error {\n\t\tcc.mu.Lock()', 'haveReservation, err := func() (bool, error) {\n\t\tcc.mu.Lock()')
    source = replace(source, '''\t\t\treturn errClientConnUnusable
\t\t}
\t\tcc.roundTrips++
\t\tif cc.reserved > 0 {
\t\t\t// We've already reserved a concurrency slot for this request.
\t\t\tcc.reserved--
\t\t} else if cc.cc.Reserve() != nil {
\t\t\t// We don't seem to have an available concurrency slot,
\t\t\t// so bump the pending count (requests waiting for a slot).
\t\t\tcc.pending++
\t\t}''', '''\t\t\treturn false, errClientConnUnusable
\t\t}''')
    source = replace(source, '''\t\tcc.starting++
\t\treturn nil
\t}()
\tif err != nil {
\t\treturn nil, err
\t}
\tresp, err := cc.cc.RoundTrip(req)''', '''\t\tcc.starting++
        cc.roundTrips++
        if cc.reserved == 0 { return false, nil }
        cc.reserved--
        return true, nil
    }()
    if err != nil { return nil, err }
    if !haveReservation && cc.cc.Reserve() != nil {
        cc.mu.Lock()
        cc.pending++
        cc.mu.Unlock()
    }
    resp, err := cc.cc.RoundTrip(req)''')
    return replace(source, '''\tcc.mu.Lock()
\tdefer cc.mu.Unlock()
\tif cc.doNotReuse {
\t\treturn false
\t}
\tif err := cc.cc.Reserve(); err != nil {
\t\treturn false
\t}
\tcc.reserved++
\treturn true''', '''if err := cc.cc.Reserve(); err != nil { return false }
    reserved := true
    cc.mu.Lock()
    if cc.doNotReuse { reserved = false } else { cc.reserved++ }
    cc.mu.Unlock()
    if !reserved { cc.cc.Release() }
    return reserved''')

MODULES['golang.org/x/net'] = ('v0.57.0', {
    'http2/transport_wrap.go': ('f3ec26dd40aac3b81b6b75ac4603214d7e37d461c4ec43c189063ab202d26f89', h2_reservation_lock),
})


def hopping_distinct_port(source):
    source = replace(source, '\t\tports:       ports,', '\t\tports:       ports,\n\t\tportIndex: -1,')
    return replace(source, '\tc.portIndex = rand.Intn(len(c.ports))', '''// A hop must change the destination when alternatives exist. Duplicate
    // entries and a single-port list remain valid and cannot spin forever.
    candidates := 0
    for _, port := range c.ports {
        if c.portIndex < 0 || port != c.ports[c.portIndex] { candidates++ }
    }
    if candidates == 0 { c.portIndex = rand.Intn(len(c.ports)) } else {
        choice := rand.Intn(candidates)
        for index, port := range c.ports {
            if c.portIndex >= 0 && port == c.ports[c.portIndex] { continue }
            if choice == 0 { c.portIndex = index; break }
            choice--
        }
    }''')

MODULES['github.com/sagernet/sing-quic'][1]['hysteria/hop.go'] = ('5ced1b37dd283926c6131e8721c3d359f3bfd1ce6a7f7a6f0fb0a835bb5232b9', hopping_distinct_port)


def restls_disabled_debug_reads(source):
    # Even a disabled debug function evaluates its arguments. Cross-direction
    # counters are owned by separate TLS read/write locks; don't read them just
    # for disabled logging while the other direction advances a record.
    import re
    result,count=re.subn(r'^\s*debugf\([^\n]*\)\n', '\n', source, flags=re.M)
    if count != 23:
        raise RuntimeError('Review Restls disabled debug call sites: '+str(count))
    return result

MODULES['github.com/metacubex/restls-client-go'] = ('v0.1.9', {
    'conn.go': ('2f9ed3be4dd2499288f08093cceeb8721dd3b8075fa7f5b03d07e4a7a2aa3325',restls_disabled_debug_reads),
})


def security_carrier_factory(source):
    return replace(source, 'func NewClientWithOptions(options ClientOptions) (Config, error) {\n\tif !options.Options.Enabled {\n\t\treturn nil, nil\n\t}', '''func NewClientWithOptions(options ClientOptions) (Config, error) {
 if !options.Options.Enabled { return nil,nil }
 if factory,ok:=options.Context.Value("reka.tls.client.v1").(func(context.Context,logger.ContextLogger,string,option.OutboundTLSOptions)(Config,error));ok{
  return factory(options.Context,options.Logger,options.ServerAddress,options.Options)
 }''')

MODULES['github.com/sagernet/sing-box'][1]['common/tls/client.go'] = ('c251099384a473024e96e81efba8a8ab60fd8666f50e2ab299d75f7f2aaa1030', security_carrier_factory)


def shadowtls_v2_auth_publication(source):
    source=replace(source,'import (','import (\n"sync"')
    source=replace(source,'type clientConn struct {','type clientConn struct {\n clientAccess sync.Mutex')
    source=replace(source,'return &clientConn{newConn(hashConn.Conn), hashConn}','return &clientConn{shadowConn:newConn(hashConn.dataConn()),hashConn:hashConn}')
    for signature in ['Write(p []byte) (n int, err error)','WriteVectorised(buffers []*buf.Buffer) error']:
        source=replace(source,'func (c *clientConn) '+signature+' {','func (c *clientConn) '+signature+' {\n c.clientAccess.Lock();defer c.clientAccess.Unlock()')
    return source

MODULES['github.com/sagernet/sing-shadowtls'][1]['v2_client.go'] = ('cfd360330e85fc9cc002fede7334e6fcaea75704115fa2ef20203a34753d9172',shadowtls_v2_auth_publication)


def shadowtls_v2_handshake_join(source):
    source = replace(source, '\t\tgo bufio.Copy(hashConn, handshakeConn)', '''		copyDone := make(chan struct{})
		go func() {
			defer close(copyDone)
			bufio.Copy(hashConn, handshakeConn)
		}()''')
    source = replace(source, '\t\t\thandshakeConn.Close()\n\t\t\ts.handler.NewConnectionEx(ctx, bufio.NewCachedConn(newConn(conn), request)', '\t\t\thandshakeConn.Close()\n\t\t\t<-copyDone\n\t\t\ts.handler.NewConnectionEx(ctx, bufio.NewCachedConn(newConn(conn), request)')
    return source


MODULES['github.com/sagernet/sing-shadowtls'][1]['service.go'] = ('51da1ff27b1c3a926b7f5e25c857b9d6df8a82ebfd6d927e22248cd28e7bd225', shadowtls_v2_handshake_join)


def shadowtls_v2_post_handshake(source):
    source = replace(source, 'type hashReadConn struct {\n\tnet.Conn\n\thmac hash.Hash\n}', '''type hashReadConn struct {
	net.Conn
	hmac hash.Hash
	access sync.Mutex
	postHandshake net.Conn
	frozen bool
}

// SetPostHandshakeConn preserves the TLS decoder for late camouflage records.
// The connection is installed before publication; the original TLS reader keeps
// using this hash connection and never recursively enters the data reader.
func (c *hashReadConn) SetPostHandshakeConn(factory func(net.Conn) net.Conn) {
	c.access.Lock()
	c.frozen = true
	c.access.Unlock()
	c.postHandshake = factory(c.Conn)
}
func (c *hashReadConn) dataConn() net.Conn {
	if c.postHandshake != nil { return c.postHandshake }
	return c.Conn
}''')
    source = replace(source, '''		conn,
		hmac.New(sha1.New, []byte(password)),''', '''		Conn: conn,
		hmac: hmac.New(sha1.New, []byte(password)),''')
    source = replace(source, '''	if err != nil {
		return
	}
	_, err = c.hmac.Write(b[:n])''', '''	c.access.Lock()
	if !c.frozen { c.hmac.Write(b[:n]) }
	c.access.Unlock()''')
    source = replace(source, 'func (c *hashReadConn) Sum() []byte {', 'func (c *hashReadConn) Sum() []byte {\n c.access.Lock(); defer c.access.Unlock()')
    return source


MODULES['github.com/sagernet/sing-shadowtls'][1]['v2_hash.go'] = ('6ec0e04900cc75dbb26c9247dd25846956dc8fa0252a5ebb3f22bc0d34038666', shadowtls_v2_post_handshake)


# Preserve the actual protocol on mixed listeners and keep failed credentials
# out of logs. The callback context survives upstream user authentication.
def inbound_socks_metadata(source):
    source = replace(source, '\tswitch version {\n\tcase socks4.Version:', '\tctx = context.WithValue(ctx, "reka.inbound.protocol.v1", map[byte]string{4:"SOCKS4", 5:"SOCKS5"}[version])\n\tswitch version {\n\tcase socks4.Version:')
    return replace(source, 'E.New("socks5: authentication failed, username=", usernamePasswordAuthRequest.Username, ", password=", usernamePasswordAuthRequest.Password)', 'E.New("socks5: authentication failed")')


def inbound_http_metadata(source):
    source = replace(source, ') error {\n\tfor {', ') error {\n\tctx = context.WithValue(ctx, "reka.inbound.protocol.v1", "HTTP")\n\tfor {')
    source = replace(source, 'E.New("http: authentication failed, username=", username, ", password=", password)', 'E.New("http: authentication failed")')
    source = replace(source, 'E.New("http: authentication failed, Proxy-Authorization=", authorization)', 'E.New("http: authentication failed")')
    # Attach diagnostics at the existing parse/forward boundary without
    # duplicating the parser, authentication, or CONNECT tunnel handling.
    source = replace(source, 'request *http.Request, source M.Socksaddr,\n) error {', '''request *http.Request, source M.Socksaddr,
) (observedErr error) {
    var observeResponse func(*http.Response)
    var proxyStatus int
    if begin, ok := ctx.Value("reka.inbound.http-observation.v1").(func(context.Context, *http.Request, string) (context.Context, func(*http.Response), func(int, error))); ok {
        var complete func(int, error)
        ctx, observeResponse, complete = begin(ctx, request, conn.RemoteAddr().String())
        defer func() { complete(proxyStatus, observedErr) }()
    }''')
    source = replace(source, 'return responseWith(request, http.StatusBadRequest).Write(conn)', 'proxyStatus = http.StatusBadRequest\n\t\treturn responseWith(request, proxyStatus).Write(conn)')
    source = replace(source, 'return E.Errors(innerErr.Load(), err, responseWith(request, http.StatusBadGateway).Write(conn))', 'proxyStatus = http.StatusBadGateway\n\t\treturn E.Errors(innerErr.Load(), err, responseWith(request, proxyStatus).Write(conn))')
    return replace(source, 'removeHopByHopHeaders(response.Header)', 'if observeResponse != nil { observeResponse(response) }\n\tremoveHopByHopHeaders(response.Header)')

MODULES['github.com/sagernet/sing'][1]['protocol/socks/handshake.go'] = ('519634a01cba3041477aac4c5a767424b9167708a96af90bdf746a970aad3be3', inbound_socks_metadata)
MODULES['github.com/sagernet/sing'][1]['protocol/http/handshake.go'] = ('fa5cf907d7a50a29ee9292cf56d6aa9fb1a4b3a82de2bc233b43653cb9cbb7e9', inbound_http_metadata)


# Keep Reka's strict response identity contract when the upstream multiplexer
# is still probing stream reuse. Bind detached reuse probes to pool lifetime.
def dns_multiplexer_identity_lifetime(source):
    source = replace(source, '\toptions    queryMultiplexerOptions', '\tprobeContext context.Context\n\tcancelProbe context.CancelFunc\n\toptions    queryMultiplexerOptions')
    source = replace(source, '\tmultiplexer := &queryMultiplexer{', '\tprobeContext, cancelProbe := context.WithCancel(context.Background())\n\tmultiplexer := &queryMultiplexer{\n\t\tprobeContext: probeContext, cancelProbe: cancelProbe,')
    source = replace(source, 'func (m *queryMultiplexer) Close() error {', 'func (m *queryMultiplexer) Close() error {\n\tm.cancelProbe()')
    source = replace(source, '\t\tresponse.Id = message.Id\n\t\tcallback(response, nil)', '\t\tif response.Id != message.Id { callback(nil, E.New("invalid DNS response identity")); return }\n\t\tresponse.Id = message.Id\n\t\tcallback(response, nil)')
    source = replace(source, '\tprobeCtx, cancel := context.WithTimeout(ctx, reuseProbeTimeout)', '\tprobeCtx, cancel := context.WithTimeout(ctx, reuseProbeTimeout)\n\tstopPool := context.AfterFunc(m.probeContext, cancel)\n\tdefer stopPool()')
    return source

MODULES['github.com/sagernet/sing-box'][1]['dns/transport/multiplexer.go'] = ('39983a6e841e82246c73cec45c9256f9647d58ad0c338747687d0fc6c36f4702', dns_multiplexer_identity_lifetime)


# The Darwin finder already obtained the concrete PID; retain it in the owner
# returned to Reka rather than discarding it after resolving the executable.
def darwin_owner_pid(source):
    return replace(source, '\t\towner := &adapter.ConnectionOwner{\n\t\t\tUserId: entry.uid,', '\t\towner := &adapter.ConnectionOwner{\n\t\t\tProcessID: entry.pid,\n\t\t\tUserId: entry.uid,')

MODULES['github.com/sagernet/sing-box'][1]['common/process/searcher_darwin_shared.go'] = ('efcd094a24fd1a30e96251441f0ad1e1f624eec10733145c436c56ef093351e5', darwin_owner_pid)
