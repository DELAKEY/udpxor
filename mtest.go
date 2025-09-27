package main

import (
	"encoding/hex"
	"log"
	"net"
	"time"
)

func main2() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 8081})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Println("Test server started on :8081")

	buffer := make([]byte, 1024)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		log.Printf("Received %d bytes: %s", n, string(buffer[:n]))

		// Имитируем обработку и отправляем несколько ответов
		for i := 0; i < 3; i++ {
			response := []byte("Response ")
			response = append(response, byte('0'+i))
			conn.WriteToUDP(buffer[:n], addr)
			log.Printf("Sent response %d to %s zzz", i, addr.String())
			time.Sleep(1 * time.Second) // Задержка между пакетами
		}
	}
}

func send() {

	targetAddr, err := net.ResolveUDPAddr("udp", "localhost:8080")
	if err != nil {
		log.Printf("Resolve error: %v", err)
		return
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Dial error: %v", err)
		return
	}
	defer targetConn.Close()

	arr := []byte{1, 2, 3, 1}

	_, err = targetConn.Write(arr)
	_, err = targetConn.Write(arr)
	_, err = targetConn.Write(arr)
	if err != nil {
		log.Printf("Write to target error: %v", err)
		return
	}
	buffer := make([]byte, 65507)
	n, _, err := targetConn.ReadFromUDP(buffer)
	log.Printf("retttt: %s", hex.EncodeToString(buffer[:n]))
}
