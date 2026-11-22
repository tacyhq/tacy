package imapro

// WriteBufferOf is the client's whole write buffer (bufio's, to its capacity): what a heap dump would find in it.
func WriteBufferOf(c *Client) []byte {
	b := c.w.AvailableBuffer()
	return b[:cap(b)]
}
