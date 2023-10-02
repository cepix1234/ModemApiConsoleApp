package authenticator

import (
	"encoding/hex"
	"errors"
	"example/blazo/modemapi/clientrequester"
	"example/blazo/modemapi/cryptohelper"
	"fmt"
)

type Authenticator struct {
	Client      clientrequester.ClientRequest
	Username    string
	Password    string
	NumbRetries int
}

func (_this *Authenticator) RetryAuthenticateUser() error {
	errorThrown := false
	err := ""
	retryNumber := 0
	for retryNumber <= _this.NumbRetries {
		fmt.Printf("Try to authenticate attempt: %d\n", retryNumber)
		err = _this.authenticateUser()
		if err != "" && retryNumber >= _this.NumbRetries {
			errorThrown = true
		}
		if err == "" && retryNumber <= _this.NumbRetries {
			break
		}
		_this.Client = clientrequester.ClientRequest{BaseUrl: _this.Client.BaseUrl}
		retryNumber++
	}
	if errorThrown {
		return errors.New(fmt.Sprintf("Authentication failed after %d retiers with error: %s", _this.NumbRetries, err))
	}
	return nil
}

func (_this *Authenticator) authenticateUser() string {
	// firstNonce := "14093ebe188a11b93bce0c09809710c68ddbb30bbf51a69cbb91ca4c35648ce4"
	firstNonce := cryptohelper.Nonce()

	data := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><request><username>%s</username><firstnonce>%s</firstnonce><mode>1</mode></request>`, _this.Username, firstNonce)

	response, responseError := _this.Client.POST("/user/challenge_login", data)
	if responseError.Code != "" {
		return fmt.Sprintf("authenticator: Authenticating user returned an error message:%s\n code:%s\n", responseError.Message, responseError.Code)
	}

	authMessage := fmt.Sprintf("%s,%s,%s", firstNonce, response.Servernonce, response.Servernonce)

	saltHex, err := hex.DecodeString(response.Salt)
	if err != nil {
		return fmt.Sprintf("authenticator: Error durring decoding response salt: %s\n", err)
	}

	clientP := cryptohelper.ClientProof(_this.Password, saltHex, response.Iterations, authMessage)

	data = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><request><clientproof>%s</clientproof><finalnonce>%s</finalnonce></request>`, clientP, response.Servernonce)
	response, responseError = _this.Client.POST("/user/authentication_login", data)
	if responseError.Code != "" {
		return fmt.Sprintf("authenticator: Authenticating user returned an error message:%s\n code:%s\n", responseError.Message, responseError.Code)
	}

	fmt.Printf("authenticator: User authenticated\n")
	return ""
}
