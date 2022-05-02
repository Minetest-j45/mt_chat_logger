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
// well this is actually mostly copypasta from Fleckenstein
// but they copypastaed it from HimbeerserverDE

var name, password, address string

type clientState uint8

const (
	csCreated clientState = iota
	csInit
	csActive
	csSleeping
)

var sc mt.Peer
var cstate clientState
var pos mt.PlayerPos

var auth struct {
	method              mt.AuthMethods
	salt, srpA, a, srpK []byte
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

		sc.SendCmd(&mt.ToSrvSRPBytesM{M: M})
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
				Minor:    4,
				Patch:    1,
				Reserved: 0,
				Formspec: 4,
				Version:  "mt_chat_logger v0.0.0",
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

			fmt.Println("Logging chat messages")
		}
	case *mt.ToCltChatMsg:
		text := cmd.Text

		log.Println(text)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("invalid args, the way to lay it out is:\n`go run . <USERNAME> <PASSWORD> <SERVER_IP>:<SERVER_PORT>`")
		return
	}

	name = os.Args[1]
	password = os.Args[2]
	address = os.Args[3]

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

	logFile, err := os.OpenFile("chat_log.txt", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags)

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
	}
}
