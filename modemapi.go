package main

import (
	"example/blazo/modemapi/authenticator"
	"example/blazo/modemapi/clientrequester"
	"fmt"
	"os"
)

func main() {
	client := clientrequester.ClientRequest{BaseUrl: "http://192.168.8.1/api"}
	auth := authenticator.Authenticator{Client: client, Username: "userNamePlaceholder", Password: "passPlaceholder", NumbRetries: 3}
	err := auth.RetryAuthenticateUser()
	if err != nil {
		fmt.Printf("Error thrown durring authentication: %s", err)
		os.Exit(1)
	}

	data := fmt.Sprintf(`<xml "1.0" encoding="UTF-8"?><request><Control>1</Control></request>`)
	fmt.Printf("Restarting modem!!\n")
	_, clientErr := auth.Client.POST("/api/device/control", data)
	if clientErr != nil {
		fmt.Printf("Error thrown durring restart post: %s", clientErr)
		os.Exit(1)
	}
	//TO restart<xml "1.0" encoding="UTF-8"?><request><Control>1</Control></request>
}
