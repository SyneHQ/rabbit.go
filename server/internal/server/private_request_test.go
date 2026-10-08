package server

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestPrivateConnectParserPreservesPayloadAndRejectsSmuggling(t *testing.T) {
	request := "CONNECT source.internal:5432 HTTP/1.1\r\nHost: source.internal:5432\r\nProxy-Authorization: Bearer opaque-token\r\n\r\n"
	reader := bufio.NewReaderSize(strings.NewReader(request+"source-bytes"), privateHeaderLimit)
	authority, token, err := readPrivateConnect(reader)
	if err != nil || authority != "source.internal:5432" || token != "opaque-token" {
		t.Fatal("valid CONNECT rejected", err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil || string(remaining) != "source-bytes" {
		t.Fatal("request parsing consumed database bytes")
	}
	for name, input := range map[string]string{
		"method":         strings.Replace(request, "CONNECT ", "GET ", 1),
		"http2":          strings.Replace(request, "HTTP/1.1", "HTTP/2.0", 1),
		"bare newline":   strings.ReplaceAll(request, "\r\n", "\n"),
		"body":           strings.Replace(request, "\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx", 1),
		"chunked":        strings.Replace(request, "\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n", 1),
		"duplicate auth": strings.Replace(request, "\r\n\r\n", "\r\npRoXy-AuThOrIzAtIoN: Bearer second\r\n\r\n", 1),
		"duplicate host": strings.Replace(request, "\r\n\r\n", "\r\nHost: source.internal:5432\r\n\r\n", 1),
		"folded":         strings.Replace(request, "Proxy-Authorization:", " Proxy-Authorization:", 1),
		"host mismatch":  strings.Replace(request, "Host: source.internal", "Host: other.internal", 1),
		"absolute URI":   strings.Replace(request, "CONNECT source", "CONNECT https://source", 1),
		"giant line":     strings.Replace(request, "opaque-token", strings.Repeat("x", privateHeaderLimit*3), 1),
		"no host":        strings.Replace(request, "Host: source.internal:5432\r\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			reader := bufio.NewReaderSize(strings.NewReader(input), privateHeaderLimit)
			if _, _, err := readPrivateConnect(reader); err == nil {
				t.Fatal("ambiguous CONNECT accepted")
			}
		})
	}
}
