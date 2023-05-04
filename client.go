package kastela

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

const vaultPath string = "api/vault"
const protectionPath string = "api/protection"
const securePath string = "api/secure"
const privacyProxyPath string = "api/proxy"
const cryptoPath string = "api/crypto"

type Operation string

const (
	OperationWrite Operation = "WRITE"
	OperationRead  Operation = "READ"
)

type EncryptionMode string

const (
	EncryptionModeAES_GCM            EncryptionMode = "AES_GCM"
	EncryptionModeCHACHA20_POLY1305  EncryptionMode = "CHACHA20_POLY1305"
	EncryptionModeXCHACHA20_POLY1305 EncryptionMode = "XCHACHA20_POLY1305"
)

type HashMode string

const (
	HashModeBLAKE2B_256 HashMode = "BLAKE2B_256"
	HashModeBLAKE2B_512 HashMode = "BLAKE2B_512"
	HashModeBLAKE2S_256 HashMode = "BLAKE2S_256"
	HashModeBLAKE3_256  HashMode = "BLAKE3_256"
	HashModeBLAKE3_512  HashMode = "BLAKE3_512"
	HashModeSHA256      HashMode = "SHA256"
	HashModeSHA512      HashMode = "SHA512"
	HashModeSHA3_256    HashMode = "SHA3_256"
	HashModeSHA3_512    HashMode = "SHA3_512"
)

type CryptoEncryptInput struct {
	KeyID      string         `json:"key_id"`
	Mode       EncryptionMode `json:"mode"`
	Plaintexts []any          `json:"plaintexts"`
}

type CryptoHMACInput struct {
	KeyID  string   `json:"key_id"`
	Mode   HashMode `json:"mode"`
	Values []any    `json:"values"`
}

type CryptoEqualInput struct {
	Hash  string `json:"hash"`
	Value any    `json:"value"`
}

type CryptoSignInput struct {
	KeyID  string `json:"key_id"`
	Values []any  `json:"values"`
}

type CryptoVerifyInput struct {
	Signature string `json:"signature"`
	Value     any    `json:"value"`
}

type VaultStoreInput struct {
	VaultID string `json:"vault_id"`
	Values  []any  `json:"values"`
}

type VaultFetchInput struct {
	VaultID string `json:"vault_id"`
	Search  any    `json:"search"`
	Size    uint64 `json:"size"`
	After   string `json:"after"`
}

type VaultGetInput struct {
	VaultID string   `json:"vault_id"`
	Tokens  []string `json:"tokens"`
}

type VaultUpdateInputValue struct {
	Token string `json:"token"`
	Value any    `json:"value"`
}

type VaultUpdateInput struct {
	VaultID string                   `json:"vault_id"`
	Values  []*VaultUpdateInputValue `json:"values"`
}

type VaultDeleteInput struct {
	VaultID string   `json:"vault_id"`
	Tokens  []string `json:"tokens"`
}

type ProtectionSealInput struct {
	ProtectionID string `json:"protection_id"`
	PrimaryKeys  []any  `json:"primary_keys"`
}

type ProtectionOpenInput struct {
	ProtectionID string `json:"protection_id"`
	Tokens       []any  `json:"tokens"`
}

type PrivacyProxyCommon struct {
	Protections map[string]string   `json:"protections"`
	Vaults      map[string][]string `json:"vaults"`
}

type PrivacyProxyOptions struct {
	Headers map[string]any `json:"headers"`
	Params  map[string]any `json:"params"`
	Body    map[string]any `json:"body"`
	Query   map[string]any `json:"query"`
	RootTag string         `json:"rootTag"`
}

type Client struct {
	kastelaUrl string
	client     *http.Client
}

// Create a new Kastela Client instance for communicating with the server. Require server information and return client instance.
func NewClient(kastelaUrl, caCertPath, clientCertPath, clientKeyPath string) *Client {
	var err error
	var caCert []byte
	if caCert, err = os.ReadFile(caCertPath); err != nil {
		log.Fatalln(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)
	var tlsCert tls.Certificate
	if tlsCert, err = tls.LoadX509KeyPair(clientCertPath, clientKeyPath); err != nil {
		log.Fatalln(err)
	}
	return &Client{
		kastelaUrl: kastelaUrl,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      certPool,
					Certificates: []tls.Certificate{tlsCert},
				},
			},
		},
	}
}

func (c *Client) request(method string, serverUrl *url.URL, data []byte) (resBody []byte, err error) {
	reqBody := bytes.NewBuffer(data)
	var req *http.Request
	if req, err = http.NewRequest(method, serverUrl.String(), reqBody); err != nil {
		return
	}
	var res *http.Response
	if res, err = c.client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()
	if resBody, err = io.ReadAll(res.Body); err != nil {
		return
	}
	if res.StatusCode != 200 {
		var errBody any
		if err = json.Unmarshal(resBody, &errBody); err != nil {
			return
		}
		switch v := errBody.(type) {
		case map[string]any:
			err = fmt.Errorf(`%s`, v["error"])
		default:
			err = fmt.Errorf(`%v`, v)
		}
	}
	return
}

// Encrypt data
//
// // sample code
// ciphertexts, err := client.CryptoEncrypt([]*kastela.CryptoEncryptInput{{KeyID: "your-key-id", Mode: kastela.EncryptionModeAES_GCM, Plaintexts: []any{"foo", "bar"}}})
func (c *Client) CryptoEncrypt(input []*CryptoEncryptInput) (ciphertexts [][]string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/encrypt`, c.kastelaUrl, cryptoPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}

	ciphertextsAny := body["ciphertexts"].([]any)
	ciphertexts = make([][]string, len(ciphertextsAny))
	for i, v := range ciphertextsAny {
		vAny := v.([]any)
		ciphertexts[i] = make([]string, len(vAny))
		for j, w := range vAny {
			ciphertexts[i][j] = w.(string)
		}
	}
	return
}

// Decrypt data
//
// // sample code
// plaintexts, err := client.CryptoDecrypt([]string{"encrypted-foo", "encrypted-bar"})
func (c *Client) CryptoDecrypt(input []string) (plaintexts []any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/decrypt`, c.kastelaUrl, cryptoPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	plaintexts = body["plaintexts"].([]any)
	return
}

// HMAC data
//
// // sample code
// hashes, err := client.CryptoHMAC([]*kastela.CryptoHMACInput{{KeyID: "your-key-id", Mode: kastela.HashModeBLAKE2B_256, Values: []any{"foo", "bar"}}})
func (c *Client) CryptoHMAC(input []*CryptoHMACInput) (hashes [][]string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/hmac`, c.kastelaUrl, cryptoPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	hashesAny := body["hashes"].([]any)
	hashes = make([][]string, len(hashesAny))
	for i, v := range hashesAny {
		vAny := v.([]any)
		hashes[i] = make([]string, len(vAny))
		for j, w := range vAny {
			hashes[i][j] = w.(string)
		}
	}
	return
}

// Compare hash and data
//
// // sample code
// result, err := client.CryptoEqual([]*kastela.CryptoEqualInput{{Hash: "your-hash", Value: "raw-value"}})
func (c *Client) CryptoEqual(input []*CryptoEqualInput) (result []bool, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/equal`, c.kastelaUrl, cryptoPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	resultAny := body["result"].([]any)
	result = make([]bool, len(resultAny))
	for i, v := range resultAny {
		result[i] = v.(bool)
	}
	return
}

// Sign data
//
// // sample code
// signatures, err := client.CryptoSign([]*kastela.CryptoSignInput{{KeyID: "your-key-id", Values: []any{"foo", "bar"}}})
func (c *Client) CryptoSign(input []*CryptoSignInput) (signatures [][]string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/sign`, c.kastelaUrl, cryptoPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	signaturesAny := body["signatures"].([]any)
	signatures = make([][]string, len(signaturesAny))
	for i, v := range signaturesAny {
		vAny := v.([]any)
		signatures[i] = make([]string, len(vAny))
		for j, w := range vAny {
			signatures[i][j] = w.(string)
		}
	}
	return
}

// Verify data signature
//
// // sample code
// result, err := client.CryptoVerify([]*kastela.CryptoVerifyInput{{Signature: "your-sign", Value: "raw-value"}})
func (c *Client) CryptoVerify(input []*CryptoVerifyInput) (result []bool, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/verify`, c.kastelaUrl, cryptoPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	resultAny := body["result"].([]any)
	result = make([]bool, len(resultAny))
	for i, v := range resultAny {
		result[i] = v.(bool)
	}
	return
}

// Store vault data
//
//	// sample code
//	tokens, err = client.VaultStore([]*kastela.VaultStoreInput{{VaultID: "your-vault-id", Values: []any{ "foo", 1 }}})
func (c *Client) VaultStore(input []*VaultStoreInput) (tokens [][]string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/store`, c.kastelaUrl, vaultPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	tokensAny := body["tokens"].([]any)
	tokens = make([][]string, len(tokensAny))
	for i, v := range tokensAny {
		vAny := v.([]any)
		tokens[i] = make([]string, len(vAny))
		for j, w := range vAny {
			tokens[i][j] = w.(string)
		}
	}
	return
}

// Search vault data by indexed column
//
//	// sample code
//	tokens, err = client.VaultFetch(&VaultFetchInput{VaultID: "your-vault-id", Search: "foo", Size: 10, After: "bar"})
func (c *Client) VaultFetch(input *VaultFetchInput) (tokens []string, err error) {
	body := map[string]any{
		"vault_id": input.VaultID,
		"search":   input.Search,
	}
	if input.Size > 0 {
		body["size"] = input.Size
	}
	if len(input.After) > 0 {
		body["after"] = input.After
	}
	var reqBody []byte
	if reqBody, err = json.Marshal(body); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/fetch`, c.kastelaUrl, vaultPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	tokensAny := body["tokens"].([]any)
	tokens = make([]string, len(tokensAny))
	for i, v := range tokensAny {
		tokens[i] = v.(string)
	}
	return
}

// Get vault data
//
//	// sample code
//	values, err = client.VaultGet([]*VaultGetInput{{VaultID: "your-vault-id", Tokens: []string{ "foo", "bar"}}})
func (c *Client) VaultGet(input []*VaultGetInput) (values [][]any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/get`, c.kastelaUrl, vaultPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	valuesAny := body["values"].([]any)
	values = make([][]any, len(valuesAny))
	for i, v := range valuesAny {
		values[i] = v.([]any)
	}
	return
}

// Update vault data
//
//	// sample code
//	err = client.VaultUpdate([]*VaultUpdateInput{{VaultID: "your-vault-id", Values: []*VaultUpdateInputValue{{Token: "foo", Value: 123456}}}})
func (c *Client) VaultUpdate(input []*VaultUpdateInput) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/update`, c.kastelaUrl, vaultPath)); err != nil {
		return
	}
	_, err = c.request("POST", serverUrl, reqBody)
	return
}

// Remove vault data
//
//	// sample code
//	err = client.VaultDelete([]*VaultDeleteInput{{VaultID: "your-vault-id", Tokens: []string{"foo", "bar"}}})
func (c *Client) VaultDelete(input []*VaultDeleteInput) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/delete`, c.kastelaUrl, vaultPath)); err != nil {
		return
	}
	_, err = c.request("POST", serverUrl, reqBody)
	return
}

// Encrypt data protection
//
//	// sample code
//	err := client.protectionSeal([]*ProtectionSealInput{ProtectionID: "your-protection-id", PrimaryKeys: []any{1, 2, 3}})
func (c *Client) ProtectionSeal(input []*ProtectionSealInput) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/seal`, c.kastelaUrl, protectionPath)); err != nil {
		return
	}
	_, err = c.request("POST", serverUrl, reqBody)
	return
}

// Decrypt data protection
//
//	// sample code
//	values, err := client.protectionOpen([]*ProtectionOpenInput{ProtectionID: "your-protection-id", Tokens: []any{ "foo", "bar", "baz" }})
func (c *Client) ProtectionOpen(input []*ProtectionOpenInput) (values [][]any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(input); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/open`, c.kastelaUrl, protectionPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	values = [][]any{}
	for _, v := range body["values"].([]any) {
		values = append(values, v.([]any))
	}
	return
}

// Initialize secure protection
//
//	// sample code
//	credential, err := client.SecureProtectionInit("WRITE", []string{"your-protection-id"}, 5)
func (c *Client) SecureProtectionInit(operation Operation, protectionIDs []string, ttl int) (credential string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{
		"operation":      operation,
		"protection_ids": protectionIDs,
		"ttl":            ttl,
	}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/protection/init`, c.kastelaUrl, securePath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	credential = body["credential"].(string)
	return
}

// Commit secure protection
//
//	// sample code
//	err := client.SecureProtectionCommit("your-credential")
func (c *Client) SecureProtectionCommit(credential string) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{
		"credential": credential,
	}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/protection/commit`, c.kastelaUrl, securePath)); err != nil {
		return
	}
	_, err = c.request("POST", serverUrl, reqBody)
	return
}

// Initialize secure vault
//
//	// sample code
//	credential, err := client.SecureVaultInit("WRITE", []string{"your-vault-id"}, 5)
func (c *Client) SecureVaultInit(operation Operation, vaultIDs []string, ttl int) (credential string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{
		"operation": operation,
		"vault_ids": vaultIDs,
		"ttl":       ttl,
	}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/vault/init`, c.kastelaUrl, securePath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	credential = body["credential"].(string)
	return
}

// Proxying request to another host
//
//	response, err := client.PrivacyProxyRequest("json", "https://enskbwhbhec7l.x.pipedream.net/:_phone/:_salary", "post", kastela.PrivacyProxyCommon{
//	    Protections: map[string]string{
//	        "_email": "124edec8-530e-4fd2-a04b-d4dc21ce625a",
//	        "_phone": "9f53aa3b-7214-436d-af9b-d2952be9f0c4",
//	    }, Vaults: map[string][]string{
//	        "_salary": {
//	            "c5f9236d-aea0-46a5-a2fe-fb75c0596c87",
//	            "salary",
//	        },
//	    },
//	}, &kastela.PrivacyProxyOptions{
//	    Headers: map[string]any{
//	        "_email": "1",
//	    },
//	    Params: map[string]any{
//	        "_phone":  "1",
//	        "_salary": "01GQEATT1Q3NKKDC3A2JSMN7ZJ",
//	    },
//	    Body: map[string]any{
//	        "name":    "jhon daeng",
//	        "_email":  "1",
//	        "_phone":  "1",
//	        "_salary": "01GQEATT1Q3NKKDC3A2JSMN7ZJ",
//	    },
//	    Query: map[string]any{
//	        "id":     "123456789",
//	        "_email": "1",
//	    },
//	})
func (c *Client) PrivacyProxyRequest(bodyType string, targetUrl string, method string, common PrivacyProxyCommon, options *PrivacyProxyOptions) (response any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{
		"type":    bodyType,
		"url":     targetUrl,
		"method":  method,
		"common":  common,
		"options": options,
	}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s`, c.kastelaUrl, privacyProxyPath)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	response = body
	return
}
