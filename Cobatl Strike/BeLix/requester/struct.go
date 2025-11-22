package requester

import "net/http"

type ReqProfile struct {
	GETURL  string
	PSTURL	string
	Agent	string

	Count 	int

	Client 	*http.Client
	Req 	*http.Request
}