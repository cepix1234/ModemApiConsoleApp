package clientrequester

type ClientResponse struct {
	Token        string `xml:"token"`
	NewType      string `xml:"newType"`
	Iterations   int    `xml:"iterations"`
	Salt         string `xml:"salt"`
	Modeselected string `xml:"modeselected"`
	Servernonce  string `xml:"servernonce"`
	Rsae         string `xml:"rsae"`
	Rsan         string `xml:"rsan"`
}

type ClientError struct {
	Message string `xml:"message"`
	Code    string `xml:"code"`
}
