package internal

func Task(cmd uint32, data []byte) (uint32, []byte) {
	switch cmd {
	default:
		return 32,[]byte("not a command")
	}
}