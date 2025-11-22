package requester

import (
	"belin/config"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func New(id int) ReqProfile {
	GETURL := "http://" + config.HOST + config.GPTH
	PSTURL := "http://" + config.HOST + config.PPTH

	newReq := ReqProfile{
		GETURL: GETURL,
		PSTURL: PSTURL+fmt.Sprintf("%d", id), 
		Agent: "aaaa",
		Client: &http.Client{Timeout: time.Duration(config.TOUT) * time.Second},
	}

	return newReq
}

func (r *ReqProfile) Post(data []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", r.PSTURL, bytes.NewBuffer(data))
	if err != nil {return nil, err}
 
	req.Header.Set("User-Agent", r.Agent)
	req.Header.Set("Accept", "*/*")

	resp, err := r.Client.Do(req)
	if err != nil {return nil, err}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Code not 200")
	}

	return resp, nil
}

func (r *ReqProfile) Get(cookies string) (*http.Response, error) {
	req, err := http.NewRequest("GET", r.GETURL, nil)
	if err != nil {return nil, err}

	req.Header.Set("User-Agent", r.Agent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cookie", cookies)

	resp, err := r.Client.Do(req)
	if err != nil {return nil, err}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("code not 200")
	}

	return resp, nil
}