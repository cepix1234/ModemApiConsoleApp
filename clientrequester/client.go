package clientrequester

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type client interface {
	POST(url string, body string) string
	GET(url string, body string) string
}

type ClientRequest struct {
	_client   http.Client
	BaseUrl   string
	Token     string
	SessionId string
}

func (_this *ClientRequest) POST(url string, body string) (*ClientResponse, *ClientError) {
	requestToken := _this.getRequestToken()

	requestUrl := fmt.Sprintf("%s%s", _this.BaseUrl, url)
	fmt.Printf("Client: Making POST request to %s\n", requestUrl)

	requestBody := requestToReader(body)

	req, err := http.NewRequest(http.MethodPost, requestUrl, requestBody)

	if err != nil {
		fmt.Printf("client: could not create request: %s\n", err)
		os.Exit(1)
	}

	setHeadersPOST(_this, req, requestToken)

	resp := makeRequest(_this, req)

	postResponse, postError := getClientResponse(resp)

	_this.Token = getNextVerificationToken(resp)

	return postResponse, postError
}

func (_this *ClientRequest) GET(url string) (*ClientResponse, *ClientError) {
	requestUrl := fmt.Sprintf("%s%s", _this.BaseUrl, url)
	fmt.Printf("Client: Making GET request to %s\n", url)

	req, err := http.NewRequest(http.MethodGet, requestUrl, nil)

	if err != nil {
		fmt.Printf("client: could not create request: %s\n", err)
		os.Exit(1)
	}

	setCommonHeaders(req)

	resp := makeRequest(_this, req)

	if _this.SessionId == "" {
		_this.SessionId = getSessionIdFromResponse(resp)
	}

	return getClientResponse(resp)
}

func setCommonHeaders(request *http.Request) {
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0")
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Accept-Encoding", "gzip, deflate")
	request.Header.Set("Accept-Language", "en-US,en;q=0.5")
	request.Header["_ResponseSource"] = []string{"Broswer"}
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	request.Header.Set("Connection", "close")
	request.Header.Set("Referer", "http://192.168.8.1/html/index.html")
}

func setHeadersPOST(_this *ClientRequest, request *http.Request, requestToken string) {
	setCommonHeaders(request)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8;")
	request.Header.Set("charset", "UTF-8")
	request.Header.Set("Content-Length", fmt.Sprintf("%v", request.ContentLength))
	request.Header.Set("Origin", "http://192.168.8.1")
	request.Header.Set("Sec-Fetch-Dest", "empty")
	request.Header.Set("Sec-Fetch-Mode", "cors")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Te", "trailers")
	request.Header.Set("__RequestVerificationToken", getTokenForHeader(requestToken))
	if _this.SessionId != "" {
		request.Header.Set("Cookie", _this.SessionId)
	}
}

func makeRequest(_this *ClientRequest, request *http.Request) *http.Response {
	if _this._client.Timeout == 0 {
		_this._client.Timeout = 30 * time.Second
	}

	resp, err := _this._client.Do(request)

	if err != nil {
		fmt.Printf("client: error making http request: %s\n", err)
		os.Exit(1)
	}
	return resp
}

func requestToReader(request string) *bytes.Reader {
	return bytes.NewReader([]byte(request))
}

func (_this *ClientRequest) getRequestToken() string {
	if _this.Token != "" {
		return _this.Token
	}
	resp, respError := _this.GET("/webserver/token")

	if respError.Code != "" {
		fmt.Printf("client: Getting request token returned message:%s\n code:%s\n", respError.Message, respError.Code)
		os.Exit(1)
	}
	_this.Token = resp.Token
	return resp.Token
}

func getClientResponse(response *http.Response) (*ClientResponse, *ClientError) {
	responseBuf := new(bytes.Buffer)
	responseBuf.ReadFrom(response.Body)
	// fmt.Printf("client: Response: %s\n", string(responseBuf.String()))

	clientResponseStructure := &ClientResponse{}
	parseResponseErr := xml.Unmarshal([]byte(responseBuf.String()), clientResponseStructure)

	if parseResponseErr != nil {
		fmt.Printf("client: Could not parse response body: %s\n", parseResponseErr)
		os.Exit(1)
	}

	clientErrorStructure := &ClientError{}
	parseErrorErr := xml.Unmarshal([]byte(responseBuf.String()), clientErrorStructure)

	if parseErrorErr != nil {
		fmt.Printf("client: Could not parse response body: %s\n", parseErrorErr)
		os.Exit(1)
	}
	return clientResponseStructure, clientErrorStructure
}

func getSessionIdFromResponse(response *http.Response) string {
	cookies := response.Header["Set-Cookie"]
	if len(cookies) > 0 {
		cookie := cookies[0]
		sessionId := strings.Split(cookie, ";")[0]
		return sessionId
	}
	return ""
}

func getNextVerificationToken(response *http.Response) string {
	return response.Header.Get("__RequestVerificationToken")
}

func getTokenForHeader(token string) string {
	if len(token) > 32 {
		return token[32:]
	}
	return token
}
