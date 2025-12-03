package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

type XORCipher struct {
	key []byte
}

func NewXORCipher(key []byte) *XORCipher {
	return &XORCipher{key: key}
}

func (x *XORCipher) Process(data []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ x.key[i%len(x.key)]
	}
	return result
}

type ClientSession struct {
	clientAddr   *net.UDPAddr
	targetConn   *net.UDPConn
	serverConn   *net.UDPConn
	cipher       *XORCipher
	lastActivity time.Time
}

type UDPProxy struct {
	listenAddr  string
	targetAddr  string
	cipher      *XORCipher
	sessions    map[string]*ClientSession
	sessionsMux sync.RWMutex
}

func NewUDPProxy(listenAddr, targetAddr string, key []byte) *UDPProxy {
	proxy := &UDPProxy{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		cipher:     NewXORCipher(key),
		sessions:   make(map[string]*ClientSession),
	}

	// Запускаем очистку неактивных сессий
	go proxy.cleanupSessions()

	return proxy
}

func (p *UDPProxy) Start() error {
	listenAddr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("UDP proxy started on %s -> %s", p.listenAddr, p.targetAddr)

	buffer := make([]byte, 65507)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		go p.handlePacket(conn, clientAddr, buffer[:n])
	}
}

func (p *UDPProxy) handlePacket(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	session := p.getSession(serverConn, clientAddr)
	session.lastActivity = time.Now()

	// Расшифровываем и отправляем на целевой сервер
	decrypted := p.cipher.Process(data)
	//log.Printf("Forwarding %d bytes from %s to %s data %s", len(decrypted), clientAddr.String(), session.targetConn.RemoteAddr(), hex.EncodeToString(data))

	_, err := session.targetConn.Write(decrypted)
	if err != nil {
		log.Printf("Write to target error: %v", err)
		p.removeSession(clientAddr.String())
		return
	}
}

func (p *UDPProxy) getSession(serverConn *net.UDPConn, clientAddr *net.UDPAddr) *ClientSession {
	clientID := clientAddr.String()

	p.sessionsMux.RLock()
	session, exists := p.sessions[clientID]
	p.sessionsMux.RUnlock()

	if exists {
		return session
	}

	p.sessionsMux.Lock()
	defer p.sessionsMux.Unlock()

	// Двойная проверка
	if session, exists := p.sessions[clientID]; exists {
		return session
	}

	// Создаем новую сессию
	targetAddr, err := net.ResolveUDPAddr("udp", p.targetAddr)
	if err != nil {
		log.Printf("Resolve target error: %v", err)
		return nil
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Dial target error: %v", err)
		return nil
	}

	session = &ClientSession{
		clientAddr:   clientAddr,
		targetConn:   targetConn,
		serverConn:   serverConn,
		cipher:       p.cipher,
		lastActivity: time.Now(),
	}

	p.sessions[clientID] = session

	// Запускаем горутину для приема ответов от целевого сервера
	go p.forwardResponses(session)

	return session
}

func (p *UDPProxy) forwardResponses(session *ClientSession) {
	buffer := make([]byte, 65507)

	for {
		session.targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := session.targetConn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Проверяем активность сессии
				if time.Since(session.lastActivity) > 30*time.Second {
					log.Printf("Session %s timeout", session.clientAddr.String())
					break
				}
				continue
			}
			//log.Printf("Read from target error: %v", err)
			break
		}

		// Шифруем и отправляем обратно клиенту
		encrypted := session.cipher.Process(buffer[:n])
		_, err = session.serverConn.WriteToUDP(encrypted, session.clientAddr)
		if err != nil {
			log.Printf("Write to client error: %v", err)
			break
		}

		//log.Printf("Forwarded %d bytes to %s", n, session.clientAddr.String())
	}

	p.removeSession(session.clientAddr.String())
	session.targetConn.Close()
}

func (p *UDPProxy) removeSession(clientID string) {
	p.sessionsMux.Lock()
	defer p.sessionsMux.Unlock()

	if session, exists := p.sessions[clientID]; exists {
		session.targetConn.Close()
		delete(p.sessions, clientID)
		log.Printf("Session removed: %s", clientID)
	}
}

func (p *UDPProxy) cleanupSessions() {
	for {
		time.Sleep(60 * time.Second)

		p.sessionsMux.Lock()
		now := time.Now()
		for clientID, session := range p.sessions {
			if now.Sub(session.lastActivity) > 60*time.Second {
				log.Printf("Cleaning up inactive session: %s", clientID)
				session.targetConn.Close()
				delete(p.sessions, clientID)
			}
		}
		p.sessionsMux.Unlock()
	}
}

func main() {
	godotenv.Load()
	skey := os.Getenv("UDP_KEY")
	target := os.Getenv("UDP_TARGET")

	fmt.Println("KEY = ", skey)
	var c = make(chan interface{})
	// Статичный ключ (16 байт)
	//key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}

	key, _ := hex.DecodeString(skey)
	proxy := NewUDPProxy(":3000", target, key)
	//go main2()
	//go send()
	go proxy.Start()
	fmt.Println("run")
	<-c
}
