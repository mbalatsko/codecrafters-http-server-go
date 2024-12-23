package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

const httpVersion = "HTTP/1.1"
const eol = "\r\n"

type HttpStatus struct {
	Code int
}

func (status *HttpStatus) String() string {
	return fmt.Sprintf("%d %s", status.Code, http.StatusText(status.Code))
}

type HttpResponse struct {
	Status  HttpStatus
	Headers map[string]string
	Body    string
}

func makeHttpResponse(status HttpStatus) *HttpResponse {
	return &HttpResponse{
		Status:  status,
		Headers: make(map[string]string),
		Body:    "",
	}
}

func (response *HttpResponse) String() string {
	return fmt.Sprintf("%s %s", httpVersion, &response.Status) + eol + eol
}

func main() {
	addr := "0.0.0.0:4221"
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("Failed to bind to port 4221")
		os.Exit(1)
	}
	log.Printf("Started TCP server on %s\n", addr)

	conn, err := l.Accept()
	if err != nil {
		log.Fatal("Error accepting connection: ", err.Error())
		os.Exit(1)
	}
	log.Printf("Connection received from %s\n", conn.RemoteAddr())
	defer conn.Close()

	response := makeHttpResponse(HttpStatus{200}).String()
	_, err = conn.Write([]byte(response))
	if err != nil {
		log.Fatal("Error writting to connection: ", err.Error())
		os.Exit(1)
	}
}
