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
