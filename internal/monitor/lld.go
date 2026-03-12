package monitor

type LLDItem struct {
	SN string `json:"{#SN}"` //nolint:tagliatelle
	CN string `json:"{#CN}"` //nolint:tagliatelle
}

type LLDResponse struct {
	Data []LLDItem `json:"data"`
}
