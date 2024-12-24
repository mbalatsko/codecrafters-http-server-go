package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const httpVersion = "HTTP/1.1"
const eol = "\r\n"

var directory string

type Headers map[string]string

type HandlerFunc func(*Request, *Response)

type Method string

const (
	MethodGet  Method = "GET"
	MethodPost Method = "POST"
)

type Encoding string

const (
	EncodingGzip Encoding = "gzip"
)

type Response struct {
	Status  ResponseStatus
	Headers Headers
	Body    []byte
}

type ResponseStatus struct {
	Code int
}

func newResponse() *Response {
	return &Response{
		Headers: make(map[string]string),
		Body:    make([]byte, 0),
	}
}

func (status *ResponseStatus) String() string {
	return fmt.Sprintf("%d %s", status.Code, http.StatusText(status.Code))
}

func (response *Response) SetStatus(code int) {
	response.Status = ResponseStatus{code}
}

func (response *Response) SetHeader(header string, value string) {
	response.Headers[header] = value
}

func (response *Response) SetBody(body []byte, contentType string) {
	response.Body = body
	response.SetHeader("Content-Length", strconv.Itoa(len(body)))
	response.SetHeader("Content-Type", contentType)
}

func (response *Response) SetEmptyBody() {
	response.Body = []byte{}
	response.SetHeader("Content-Length", "0")
}

func (response *Response) GzipBody() {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	defer zw.Close()
	_, err := zw.Write(response.Body)
	if err != nil {
		log.Fatalf("Failed to gzip body: %s", response.Body)
		return
	}

	response.SetBody(buf.Bytes(), response.Headers["Content-Type"])
	response.SetHeader("Content-Encoding", "gzip")
}

func (resp *Response) Combine(req *Request) []byte {
	reqAccEnc, isSet := req.Headers["Accept-Encoding"]
	if isSet {
		reqAccEncParts := strings.Split(reqAccEnc, ", ")
		outerLoop:
		for _, enc := range reqAccEncParts {
			switch Encoding(enc) {
			case EncodingGzip:
				resp.GzipBody()
				break outerLoop
			default:
				continue
			}
		}
	}

	// Status section
	statusSection := fmt.Sprintf("%s %s", httpVersion, &resp.Status)

	// Headers section
	var headersSection string
	for header, value := range resp.Headers {
		headersSection += fmt.Sprintf("%s: %s", header, value) + eol
	}

	// concat and convert to bytes
	topSectionsByteA := []byte(statusSection + eol + headersSection + eol)

	// append body bytes
	return append(topSectionsByteA, resp.Body...)
}

type Request struct {
	Host    net.Addr
	Method  Method
	Path    string
	Headers Headers
	Body    []byte
}

func parseFirstRequestLine(s string) (method Method, path string, err error) {
	sParts := strings.Split(s, " ")
	if len(s) < 3 {
		return method, path, fmt.Errorf("error parsing request first line")
	}

	switch Method(sParts[0]) {
	case MethodGet, MethodPost:
		method = Method(sParts[0])
	default:
		return method, path, fmt.Errorf("unsupported method %s given", sParts[0])
	}

	parsedUrl, err := url.Parse(sParts[1])
	if err != nil {
		return method, path, fmt.Errorf("error occurred in path parsing %s", err.Error())
	}

	return method, parsedUrl.Path, nil
}

func parseHeader(headerLine string) (key string, value string, err error) {
	keyIdx := strings.Index(headerLine, ": ")
	if keyIdx == -1 {
		return key, value, fmt.Errorf("no key found in header line: %s", headerLine)
	}
	return headerLine[:keyIdx], headerLine[keyIdx+2:], nil
}

func parseHeaders(headersLines []string) (Headers, error) {
	headers := make(Headers)
	for _, hl := range headersLines {
		k, v, err := parseHeader(hl)
		if err != nil {
			return nil, err
		}
		headers[k] = v
	}
	return headers, nil
}

func ReadAll(conn net.Conn) ([]byte, error) {
	const buffSize = 512
	b := make([]byte, 0, buffSize)
	for {
		n, err := conn.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}

		if len(b) == cap(b) {
			// Add more capacity (let append pick how much).
			b = append(b, 0)[:len(b)]
		}

		if n < buffSize {
			return b, nil
		}
	}
}

func parseRequest(conn net.Conn) (*Request, error) {
	rawRequestBytes, err := ReadAll(conn)
	if err != nil {
		return nil, err
	}

	rawRequest := string(rawRequestBytes)
	rawRequestParts := strings.Split(rawRequest, eol)

	if len(rawRequestParts) < 3 {
		return nil, fmt.Errorf("content is too short")
	}

	method, path, err := parseFirstRequestLine(rawRequestParts[0])
	if err != nil {
		return nil, err
	}

	headersEndIdx := slices.Index(rawRequestParts, "")
	if headersEndIdx == -1 {
		return nil, fmt.Errorf("malformed request, end of headers not found")
	}

	headers, err := parseHeaders(rawRequestParts[1:headersEndIdx])
	if err != nil {
		return nil, err
	}

	body := []byte(strings.Join(rawRequestParts[headersEndIdx+1:], eol))

	return &Request{
		Host:    conn.RemoteAddr(),
		Method:  method,
		Path:    path,
		Headers: headers,
		Body:    body,
	}, nil
}

type Route struct {
	Path    regexp.Regexp
	Method  Method
	Handler HandlerFunc
}

type Router struct {
	Routes         []Route
	DefaultHandler HandlerFunc
}

func newRouter(defaultHandler HandlerFunc, routes ...Route) *Router {
	return &Router{
		Routes:         routes,
		DefaultHandler: defaultHandler,
	}
}

func (r *Router) getHandler(path string, method Method) HandlerFunc {
	for _, rr := range r.Routes {
		if rr.Path.MatchString(path) && rr.Method == method {
			return rr.Handler
		}
	}
	return r.DefaultHandler
}

type Server struct {
	Addr     string
	Listener net.Listener
	Router   *Router
}

func newServer(addr string, router *Router) *Server {
	return &Server{
		Addr:   addr,
		Router: router,
	}
}

func (server *Server) Start() error {
	l, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal("Failed to bind to port")
		return err
	}
	server.Listener = l
	log.Printf("Started TCP server on %s\n", l.Addr().String())
	return nil
}

func (server *Server) ServeForever() error {
	for {
		conn, err := server.Listener.Accept()
		if err != nil {
			log.Fatal("Error accepting connection: ", err.Error())
			continue
		}
		log.Printf("Connection received from %s\n", conn.RemoteAddr())

		go func() {
			defer conn.Close()

			req, err := parseRequest(conn)
			if err != nil {
				log.Fatalf("Failed to parse request: %s, closing connection", err.Error())
				return
			}
			resp := newResponse()
			server.Router.getHandler(req.Path, req.Method)(req, resp)
			_, err = conn.Write(resp.Combine(req))
			if err != nil {
				log.Fatal("Error writing to connection: ", err.Error())
				return
			}
		}()
	}
}

func NotFoundHandler(req *Request, resp *Response) {
	resp.SetStatus(404)
}

func SuccessHandler(req *Request, resp *Response) {
	resp.SetStatus(200)
}

func EchoHandler(req *Request, resp *Response) {
	resp.SetStatus(200)
	echoStr := strings.Split(req.Path, "/")[2]
	resp.SetBody([]byte(echoStr), "text/plain")
}

func UserAgentHandler(req *Request, resp *Response) {
	resp.SetStatus(200)
	userAgent := req.Headers["User-Agent"]
	resp.SetBody([]byte(userAgent), "text/plain")
}

func GetFileHandler(req *Request, resp *Response) {
	filename := strings.Split(req.Path, "/")[2]
	data, err := os.ReadFile(path.Join(directory, filename))
	if err != nil {
		resp.SetStatus(404)
		return
	}

	resp.SetStatus(200)
	resp.SetBody(data, "application/octet-stream")
}

func CreateFileHandler(req *Request, resp *Response) {
	filename := strings.Split(req.Path, "/")[2]
	err := os.WriteFile(path.Join(directory, filename), req.Body, 0644)
	if err != nil {
		resp.SetStatus(500)
		return
	}

	resp.SetStatus(201)
}

func init() {
	flag.StringVar(&directory, "directory", "/tmp", "Directory to take files")
	flag.Parse()
}

func main() {
	addr := "0.0.0.0:4221"

	router := newRouter(
		NotFoundHandler,
		Route{*regexp.MustCompile(`^/$`), MethodGet, SuccessHandler},
		Route{*regexp.MustCompile(`^/echo/\w+$`), MethodGet, EchoHandler},
		Route{*regexp.MustCompile(`^/user\-agent$`), MethodGet, UserAgentHandler},
		Route{*regexp.MustCompile(`^/files/\w+$`), MethodGet, GetFileHandler},
		Route{*regexp.MustCompile(`^/files/\w+$`), MethodPost, CreateFileHandler},
	)
	server := newServer(addr, router)

	err := server.Start()
	if err != nil {
		os.Exit(1)
	}

	err = server.ServeForever()
	if err != nil {
		os.Exit(1)
	}
}
