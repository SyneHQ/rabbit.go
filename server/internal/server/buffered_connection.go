package server

import (
	"bufio"
	"fmt"
	"net"
)

// Preserve payload bytes read ahead while parsing the data-pairing frame.
type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConnection) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedConnection) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return fmt.Errorf("connection does not support half-close")
}
