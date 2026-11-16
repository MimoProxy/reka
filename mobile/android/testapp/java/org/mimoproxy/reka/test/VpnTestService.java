package org.mimoproxy.reka.test;
import android.app.*;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import org.json.*;
import org.mimoproxy.reka.Native;
import org.mimoproxy.reka.ConnectionOwner;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;
/** Isolated, short-lived production library VPN acceptance. */
public final class VpnTestService extends VpnService {
 private long handle; private int protectCalls; private long id; private boolean full,networkCycle; private final java.util.concurrent.atomic.AtomicInteger processCalls=new java.util.concurrent.atomic.AtomicInteger(),processMatches=new java.util.concurrent.atomic.AtomicInteger(),legacyProcessCalls=new java.util.concurrent.atomic.AtomicInteger(); private ConnectionOwner connectionOwner; private final StringBuilder report=new StringBuilder();
 private void log(String s){Log.i("RekaVPNTest",s);report.append(s).append('\n');}
 private JSONObject call(String method,JSONObject params)throws Exception{JSONObject req=new JSONObject().put("id",++id).put("method",method);if(params!=null)req.put("params",params);JSONObject r=new JSONObject(Native.call(handle,req.toString()));if(r.has("error"))throw new Exception(r.toString());return r.getJSONObject("result");}
 private Native.Host host=new Native.Host(){public boolean protect(int fd){protectCalls++;return VpnTestService.this.protect(fd);}public String findProcessInfo(String network,String source,String destination){processCalls.incrementAndGet();if(connectionOwner==null)connectionOwner=new ConnectionOwner(VpnTestService.this);String found=connectionOwner.findProcessInfo(network,source,destination);try{JSONObject info=new JSONObject(found);if(info.optString("path").equals(getPackageName()) && info.has("uid") && info.getLong("uid")==android.os.Process.myUid())processMatches.incrementAndGet();}catch(JSONException unavailable){}return found;}public String findProcess(String network,String source,String destination){legacyProcessCalls.incrementAndGet();return "";}public byte[] seal(byte[]p){return p;}public byte[] open(byte[]p){return p;}public void onMessage(String s){}};
 @Override public int onStartCommand(Intent intent,int flags,int startId){
  full=intent!=null && intent.getBooleanExtra("full",false);
  networkCycle=intent!=null && intent.getBooleanExtra("network-cycle",false);
  NotificationManager nm=getSystemService(NotificationManager.class);nm.createNotificationChannel(new NotificationChannel("vpn","VPN acceptance",NotificationManager.IMPORTANCE_LOW));startForeground(14,new Notification.Builder(this,"vpn").setContentTitle("Reka VPN acceptance").setSmallIcon(android.R.drawable.ic_lock_lock).build());
  new Thread(()->runTest(),"reka-vpn-test").start();return START_NOT_STICKY;
 }
 private void runTest(){boolean pass=true;try{
  log("scope="+(full?"IPv4 + IPv6 default routes":"selected test-host routes"));
  for(String mode:new String[]{"all","include","exclude"}){
   Builder b=builder("Reka acceptance "+mode,1500);
   if(mode.equals("include"))b.addAllowedApplication(getPackageName());if(mode.equals("exclude"))b.addDisallowedApplication(getPackageName());
   ParcelFileDescriptor fd=b.establish();if(fd==null)throw new Exception("VPN permission missing");
   String profile="schema-version: 1\ndns:\n nameserver: [223.5.5.5]\n default-nameserver: [223.5.5.5]\n hosts: [{id: fixture.reka.test, addresses: [192.0.2.7]}]\n use-hosts: true\nrules:\n - {id: probe, match: {and: [{ip-cidr: 223.5.5.5/32}, {dst-port: '443'}, {network: tcp}]}, outbound: direct}\n - {id: final, match: {all: true}, outbound: direct}\n";
   String appConfig=mode.equals("all")?"":"  apps: ["+getPackageName()+"]\n";
   String local="network:\n mode: tun\n tun:\n  stack: mixed\n  address6: 'fdfe:dcba:9876::1/126'\n  dns-hijack: true\n  routes: [223.5.5.5/32, '2400:3200::1/128', 198.18.0.0/16]\n  app-mode: "+mode+"\n"+appConfig;
   if(full)local=local.replace("  routes: [223.5.5.5/32, '2400:3200::1/128', 198.18.0.0/16]\n","");
   File root=new File(getFilesDir(),"vpn-"+mode+"-"+System.nanoTime());handle=Native.startVPN(root.getPath(),profile,local,host,fd.getFd());fd.close();if(handle==0)throw new Exception(Native.lastError());
   JSONObject hello=call("Hello",new JSONObject().put("versions",new JSONArray().put(1)));
   if(!hello.getString("server").equals("reka/"+BuildVersion.VERSION))throw new Exception("API version mismatch: "+hello);
   log("API build version: "+hello.getString("server"));
   JSONObject status=call("GetStatus",null);if(!status.optString("start_error").isEmpty())throw new Exception(status.toString());
   Thread.sleep(600);if(!awaitDNS("223.5.5.5",!mode.equals("exclude")))throw new Exception("app routing failed: "+mode);
   log(mode+" IPv4 DNS app routing PASS");
   if(!mode.equals("exclude")){
    if(!awaitDNS("2400:3200::1",true))throw new Exception("IPv6 hijack failed");log(mode+" IPv6 DNS PASS");
    https("223.5.5.5");log(mode+" IPv4 HTTPS forwarded PASS");
    https("2400:3200::1");log(mode+" IPv6 HTTPS forwarded PASS");
    if(mode.equals("all") && networkCycle)networkTransition();
    // A deliberately different package must not reject our socket. Then the
    // actual UID lookup must select this package's reject rule over final direct.
    processRule("org.mimoproxy.reka.not-installed");https("223.5.5.5");
    // Correct package with the wrong UID must fall through, with one rich owner lookup.
    processRule(getPackageName(),android.os.Process.myUid()+1);
    int beforeWrongUID=processCalls.get();https("223.5.5.5");
    if(processCalls.get()!=beforeWrongUID+1)throw new Exception("wrong UID AND package queried owner more than once");
    processRule(getPackageName());
    int beforeMatchedOwner=processCalls.get();
    boolean processRejected=false;try{https("223.5.5.5");}catch(IOException expected){processRejected=true;}
    if(!processRejected || processMatches.get()==0 || processCalls.get()!=beforeMatchedOwner+1 || legacyProcessCalls.get()!=0)throw new Exception("rich UID AND package rule did not reject own connection with exactly one query");
    processRule("org.mimoproxy.reka.not-installed");https("223.5.5.5");
    log(mode+" real UID AND package path process rule PASS; one rich callback per connection; callbacks="+processCalls+" matches="+processMatches);
    fakeProcessRule("org.mimoproxy.reka.not-installed");
    String fakeAddress=fakeAddress();https(fakeAddress);
    fakeProcessRule(getPackageName());
    boolean fakeRejected=false;try{https(fakeAddress);}catch(IOException expected){fakeRejected=true;}
    if(!fakeRejected)throw new Exception("Fake IP process rule lost original socket tuple");
    fakeProcessRule("org.mimoproxy.reka.not-installed");https(fakeAddress);
    processRule("org.mimoproxy.reka.not-installed");
    log(mode+" Fake IP UID process rule + restore PASS");
    String device=status.getJSONObject("runtime").getJSONObject("network").getString("device");
    JSONObject result=call("CommitConfiguration",new JSONObject().put("base_revision",call("GetStatus",null).getLong("revision")).put("patch",new JSONArray().put(new JSONObject().put("op","set").put("path","/rules/probe/outbound").put("value","reject"))));
    if(!result.getString("state").equals("committed"))throw new Exception(result.toString());
    String now=call("GetStatus",null).getJSONObject("runtime").getJSONObject("network").getString("device");if(!device.equals(now))throw new Exception("TUN rebuilt");log(mode+" rule update retained TUN PASS");
    boolean rejected=false;try{https("223.5.5.5");}catch(IOException expected){rejected=true;}if(!rejected)throw new Exception("new HTTPS bypassed reject");log(mode+" new HTTPS rejected PASS");
    if(mode.equals("all")){
      String updated=local.replace("  stack: mixed", "  stack: system\n  mtu: 1400");
      JSONObject change=new JSONObject().put("base_revision",call("GetStatus",null).getLong("revision")).put("local",updated);
      JSONObject plan=call("PlanConfiguration",change);
      change.put("plan_hash",plan.getString("plan_hash")).put("operation_id","vpn-rebuild-"+System.nanoTime());
      ParcelFileDescriptor replacement=builder("Reka host rebuild",1400).establish();
      if(replacement==null)throw new Exception("replacement VPN missing");
      JSONObject request=new JSONObject().put("id",++id).put("method","CommitConfiguration").put("params",change);
      JSONObject rebuilt;
      try{rebuilt=new JSONObject(Native.reconfigureVPN(handle,replacement.getFd(),request.toString()));}finally{replacement.close();}
      if(rebuilt.has("error") || !rebuilt.getJSONObject("result").getString("state").equals("committed"))throw new Exception("rebuild failed: "+rebuilt);
      Thread.sleep(600);
      if(!awaitDNS("223.5.5.5",true) || !awaitDNS("2400:3200::1",true))throw new Exception("replacement descriptor lost traffic");
      log("explicit host VPN rebuild + stack/MTU transaction PASS");
    }

   }
   Native.stop(handle);handle=0;Thread.sleep(600);
  }
  log("scope="+(full?"IPv4 + IPv6 default routes":"selected test-host routes"));log("protect calls="+protectCalls);log("memory="+Native.memStats());
 }catch(Throwable e){pass=false;log("FAIL "+e);Log.e("RekaVPNTest","test",e);}finally{if(handle!=0){Native.stop(handle);handle=0;}log(pass?"RESULT PASS":"RESULT FAIL");try(FileOutputStream o=new FileOutputStream(new File(getFilesDir(),"vpn-report.txt"))){o.write(report.toString().getBytes("UTF-8"));}catch(Exception ignored){}stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();}}
 private boolean dnsFixture(String host)throws Exception{
  byte[] q=new byte[]{0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'f','i','x','t','u','r','e',4,'r','e','k','a',4,'t','e','s','t',0,0,1,0,1};
  try(DatagramSocket s=new DatagramSocket()){s.setSoTimeout(4000);s.send(new DatagramPacket(q,q.length,InetAddress.getByName(host),53));byte[] a=new byte[4096];DatagramPacket p=new DatagramPacket(a,a.length);s.receive(p);int n=p.getLength();return n>=4 && a[n-4]==(byte)192 && a[n-3]==0 && a[n-2]==2 && a[n-1]==7;}catch(SocketTimeoutException e){return false;}
 }
 private void processRule(String name)throws Exception{processRule(name,android.os.Process.myUid());}
 private void processRule(String name,int uid)throws Exception{
  String rules="schema-version: 1\ndns:\n nameserver: [223.5.5.5]\n default-nameserver: [223.5.5.5]\n hosts: [{id: fixture.reka.test, addresses: [192.0.2.7]}]\n use-hosts: true\nrules:\n - {id: process, match: {and: [{ip-cidr: 223.5.5.5/32}, {dst-port: '443'}, {process-path: '"+name+"'}, {uid: '"+uid+"'}]}, outbound: reject}\n - {id: probe, match: {and: [{ip-cidr: 223.5.5.5/32}, {dst-port: '443'}, {network: tcp}]}, outbound: direct}\n - {id: final, match: {all: true}, outbound: direct}\n";
  JSONObject result=call("CommitConfiguration",new JSONObject().put("base_revision",call("GetStatus",null).getLong("revision")).put("profile",rules));
  if(!result.getString("state").equals("committed"))throw new Exception(result.toString());
 }
 private void fakeProcessRule(String name)throws Exception{
  String profile="schema-version: 1\ndns:\n nameserver: [223.5.5.5]\n default-nameserver: [223.5.5.5]\n enhanced-mode: fake-ip\n fake-ip-range: 198.18.0.0/16\n fake-ip-filter-mode: whitelist\n fake-ip-filter: [dns.alidns.com]\nrules:\n - {id: process, match: {and: [{dst-port: '443'}, {process-path: '"+name+"'}, {uid: '"+android.os.Process.myUid()+"'}]}, outbound: reject}\n - {id: final, match: {all: true}, outbound: direct}\n";
  JSONObject result=call("CommitConfiguration",new JSONObject().put("base_revision",call("GetStatus",null).getLong("revision")).put("profile",profile));
  if(!result.getString("state").equals("committed"))throw new Exception(result.toString());
 }
 private String fakeAddress()throws Exception{
  ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream q=new DataOutputStream(bytes);
  q.writeShort(0x2345);q.writeShort(0x0100);q.writeShort(1);q.writeShort(0);q.writeShort(0);q.writeShort(0);
  for(String label:"dns.alidns.com".split("\\.")){q.writeByte(label.length());q.write(label.getBytes("US-ASCII"));}q.writeByte(0);q.writeShort(1);q.writeShort(1);
  try(DatagramSocket socket=new DatagramSocket()){socket.setSoTimeout(5000);socket.send(new DatagramPacket(bytes.toByteArray(),bytes.size(),InetAddress.getByName("223.5.5.5"),53));byte[] answer=new byte[4096];DatagramPacket p=new DatagramPacket(answer,answer.length);socket.receive(p);int n=p.getLength();if(n<16 || answer[6]!=0 || answer[7]!=1 || answer[10]!=0 || answer[11]!=0)throw new IOException("unexpected Fake IP DNS answer");String address=InetAddress.getByAddress(Arrays.copyOfRange(answer,n-4,n)).getHostAddress();if(!address.startsWith("198.18."))throw new IOException("not a Fake IP: "+address);return address;}
 }
 private Builder builder(String name,int mtu){Builder b=new Builder().setSession(name).setMtu(mtu).addAddress("172.19.0.1",30).addAddress("fdfe:dcba:9876::1",126).addDnsServer("172.19.0.2");if(full)b.addRoute("0.0.0.0",0).addRoute("::",0);else b.addRoute("223.5.5.5",32).addRoute("2400:3200::1",128).addRoute("198.18.0.0",16);return b;}
 private boolean awaitDNS(String host,boolean expected)throws Exception{for(int n=0;n<10;n++){if(dnsFixture(host)==expected)return true;Thread.sleep(250);}return false;}
 private void networkTransition()throws Exception{
  android.net.ConnectivityManager manager=getSystemService(android.net.ConnectivityManager.class);
  java.util.concurrent.CountDownLatch initial=new java.util.concurrent.CountDownLatch(1),lost=new java.util.concurrent.CountDownLatch(1),restored=new java.util.concurrent.CountDownLatch(1);
  java.util.concurrent.atomic.AtomicReference<android.net.Network> original=new java.util.concurrent.atomic.AtomicReference<>();
  android.net.ConnectivityManager.NetworkCallback callback=new android.net.ConnectivityManager.NetworkCallback(){
   @Override public void onAvailable(android.net.Network network){if(original.compareAndSet(null,network))initial.countDown();else if(lost.getCount()==0)restored.countDown();}
   @Override public void onLost(android.net.Network network){if(network.equals(original.get()))lost.countDown();}
  };
  manager.registerNetworkCallback(new android.net.NetworkRequest.Builder().addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI).build(),callback);
  try{
   if(!initial.await(10,java.util.concurrent.TimeUnit.SECONDS))throw new IOException("no underlying Wi-Fi for transition test");
   JSONObject before=call("GetStatus",null).getJSONObject("runtime");
   log("NETWORK_CYCLE_READY");
   if(!lost.await(40,java.util.concurrent.TimeUnit.SECONDS))throw new IOException("underlying Wi-Fi loss was not observed");
   if(!restored.await(60,java.util.concurrent.TimeUnit.SECONDS))throw new IOException("underlying Wi-Fi return was not observed");
   long began=android.os.SystemClock.elapsedRealtime();Exception last=null;boolean ready=false;
   while(android.os.SystemClock.elapsedRealtime()-began<60_000){try{https("223.5.5.5");https("2400:3200::1");if(!awaitDNS("223.5.5.5",true))throw new IOException("DNS not restored");ready=true;break;}catch(IOException error){last=error;Thread.sleep(500);}}
   if(!ready)throw new IOException("fresh dual-stack traffic did not recover",last);
   JSONObject after=call("GetStatus",null).getJSONObject("runtime");
   if(!before.getJSONObject("network").getString("device").equals(after.getJSONObject("network").getString("device")) || before.getLong("generation")!=after.getLong("generation"))throw new IOException("Wi-Fi transition rebuilt runtime/TUN");
   log("Wi-Fi loss/return + fresh IPv4/IPv6 HTTPS + DNS PASS; recovery_ms="+(android.os.SystemClock.elapsedRealtime()-began)+"; runtime/TUN unchanged");
  }finally{manager.unregisterNetworkCallback(callback);}
 }
 static void https(String address)throws Exception{
  Socket raw=new Socket();try{raw.connect(new InetSocketAddress(address,443),5000);raw.setSoTimeout(5000);
   try(SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,"dns.alidns.com",443,true)){
    SSLParameters params=tls.getSSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(params);tls.startHandshake();
    tls.getOutputStream().write("GET /resolve?name=one.one.one.one&type=1 HTTP/1.1\r\nHost: dns.alidns.com\r\nConnection: close\r\n\r\n".getBytes("US-ASCII"));
    BufferedReader reader=new BufferedReader(new InputStreamReader(tls.getInputStream(),"US-ASCII"));String line=reader.readLine();if(line==null || !line.startsWith("HTTP/1.1 200"))throw new IOException("HTTPS response: "+line);
   }
  }finally{raw.close();}
 }
 @Override public void onRevoke(){if(handle!=0){Native.stop(handle);handle=0;}stopSelf();}
}
