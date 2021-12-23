 

 package main 

  

 import ( 

         "errors" 

         "fmt" 

         "log" 

         "net" 

         "os" 

         "os/signal" 

         "syscall" 

         "time" 

  

         "github.com/HimbeerserverDE/srp" 

         "github.com/anon55555/mt" 

         "github.com/anon55555/mt/rudp" 

 ) 

  

 // mostly HimbeerserverDE/mt-multiserver-proxy copypasta 

 // a lot of things were shamelessly stolen from there

 //well this is actually mostly copypasta from Fleckenstein but they copypastaed it from HimbeerserverDE

 type clientState uint8 

  

 const ( 

         csCreated clientState = iota 

         csInit 

         csActive 

         csSleeping 

 ) 

  

 type directive uint8 

  

 const ( 

         dirLog directive = iota 

 ) 

  

 var sc mt.Peer 

 var cstate clientState 

 var dir directive 

 var pos mt.PlayerPos 

  

 var auth struct { 

         method              mt.AuthMethods 

         salt, srpA, a, srpK []byte 

 } 

  

 const ( 

         name     = "<USERNAME>" 

         password = "<PASSWORD>" 

         address  = "<SERVER_IP>:<SERVER_PORT>" 

 ) 

  

 //on chat message 

 func onChat(pkt mt.Pkt) { 

         switch cmd := pkt.Cmd.(type) { 

         case *mt.ToCltChatMsg: 

  

                 text := cmd.Text 

  

                 f, err := os.OpenFile("chat_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) 

                 if err != nil { 

                         log.Fatal(err) 

                 } 

                 if _, err := f.Write([]byte("[" + time.Now().Format("2006-01-02 15:04:05") + "]" + text + "\n")); err != nil { 

                         log.Fatal(err) 

                 } 

         } 

 } 

  

 func process(pkt mt.Pkt) { 

         switch cmd := pkt.Cmd.(type) { 

         case *mt.ToCltHello: 

                 if auth.method != 0 { 

                         fmt.Println("unexpected authentication") 

                         sc.Close() 

                         return 

                 } 

  

                 cstate++ 

  

                 if cmd.AuthMethods&mt.FirstSRP != 0 { 

                         auth.method = mt.FirstSRP 

                 } else { 

                         auth.method = mt.SRP 

                 } 

  

                 if cmd.SerializeVer != 28 { 

                         fmt.Println("invalid serializeVer") 

                         return 

                 } 

  

                 switch auth.method { 

                 case mt.SRP: 

                         var err error 

                         auth.srpA, auth.a, err = srp.InitiateHandshake() 

                         if err != nil { 

                                 fmt.Println(err) 

                                 return 

                         } 

  

                         sc.SendCmd(&mt.ToSrvSRPBytesA{ 

                                 A:      auth.srpA, 

                                 NoSHA1: true, 

                         }) 

                 case mt.FirstSRP: 

                         salt, verifier, err := srp.NewClient([]byte(name), []byte(password)) 

                         if err != nil { 

                                 fmt.Println(err) 

                                 return 

                         } 

  

                         sc.SendCmd(&mt.ToSrvFirstSRP{ 

                                 Salt:        salt, 

                                 Verifier:    verifier, 

                                 EmptyPasswd: false, 

                         }) 

                 default: 

                         fmt.Println("invalid auth method") 

                         sc.Close() 

                 } 

  

         case *mt.ToCltSRPBytesSaltB: 

                 if auth.method != mt.SRP { 

                         fmt.Println("multiple authentication attempts") 

                         return 

                 } 

  

                 var err error 

                 auth.srpK, err = srp.CompleteHandshake(auth.srpA, auth.a, []byte(name), []byte(password), cmd.Salt, cmd.B) 

                 if err != nil { 

                         fmt.Println(err) 

                         return 

                 } 

  

                 M := srp.ClientProof([]byte(name), cmd.Salt, auth.srpA, cmd.B, auth.srpK) 

                 if M == nil { 

                         fmt.Println("SRP safety check fail") 

                         return 

                 } 

  

                 sc.SendCmd(&mt.ToSrvSRPBytesM{ 

                         M: M, 

                 }) 

  

         case *mt.ToCltDisco: 

                 fmt.Println("deny access", cmd) 

                 os.Exit(0) 

  

         case *mt.ToCltAcceptAuth: 

                 auth = struct { 

                         method              mt.AuthMethods 

                         salt, srpA, a, srpK []byte 

                 }{} 

                 sc.SendCmd(&mt.ToSrvInit2{Lang: "en_US"}) 

  

         case *mt.ToCltTimeOfDay: 

                 if cstate == csInit { 

                         sc.SendCmd(&mt.ToSrvCltReady{ 

                                 Major:    5, 

                                 Minor:    5, 

                                 Patch:    0, 

                                 Reserved: 0, 

                                 Formspec: 4, 

                                 Version:  "🏳‍🌈", 

                         }) 

  

                         cstate++ 

                 } 

  

         case *mt.ToCltDeathScreen: 

                 sc.SendCmd(&mt.ToSrvRespawn{}) 

  

         case *mt.ToCltMovePlayer: 

                 pos.SetPos(cmd.Pos) 

  

         case *mt.ToCltBreath: 

                 if cstate == csActive { 

                         cstate++ 

  

                         switch dir { 

                         case dirLog: 

                                 fmt.Println("Logging chat messages") 

                         } 

                 } 

         } 

 } 

  

 func main() { 

         if len(os.Args) != 2 { 

                 fmt.Println("invalid args") 

                 return 

         } 

  

         switch os.Args[1] { 

         case "log": 

                 dir = dirLog 

         default: 

                 fmt.Println("invalid args") 

                 return 

         } 

  

         addr, err := net.ResolveUDPAddr("udp", address) 

         if err != nil { 

                 fmt.Println("address resolution fail") 

                 return 

         } 

  

         conn, err := net.DialUDP("udp", nil, addr) 

         if err != nil { 

                 fmt.Println("connection fail") 

                 return 

         } 

  

         sc = mt.Connect(conn) 

  

         go func() { 

                 init := make(chan struct{}) 

                 defer close(init) 

  

                 go func(init <-chan struct{}) { 

                         select { 

                         case <-init: 

                         case <-time.After(10 * time.Second): 

                                 fmt.Println("timeout") 

                                 sc.Close() 

                         } 

                 }(init) 

  

                 for cstate == csCreated { 

                         sc.SendCmd(&mt.ToSrvInit{ 

                                 SerializeVer: 28, 

                                 MinProtoVer:  39, 

                                 MaxProtoVer:  39, 

                                 PlayerName:   name, 

                         }) 

                         time.Sleep(500 * time.Millisecond) 

                 } 

         }() 

  

         go func() { 

                 sig := make(chan os.Signal, 1) 

                 signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP) 

                 <-sig 

  

                 sc.Close() 

                 os.Exit(0) 

         }() 

  

         for { 

                 pkt, err := sc.Recv() 

                 if err != nil { 

                         if errors.Is(err, net.ErrClosed) { 

                                 if errors.Is(sc.WhyClosed(), rudp.ErrTimedOut) { 

                                         fmt.Println("timeout") 

                                 } else { 

                                         fmt.Println("disconnect") 

                                 } 

  

                                 break 

                         } 

  

                         fmt.Println(err) 

                         continue 

                 } 

  

                 process(pkt) 

                 onChat(pkt) 

         } 

 }
