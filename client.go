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

	"golang.org/x/mod/semver"
)

type FetchVaultParams struct {
	Size  uint64
	After string
}

const expectedKastelaVersion string = "v0.2"
const vaultPath string = "api/vault"
const protectionPath string = "api/protection"
const secureChannelPath string = "api/secure-channel"
const privacyProxyPath string = "api/proxy"

type Client struct {
	kastelaUrl string
	client     *http.Client
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

// Create a new Kastela Client instance for communicating with the server.
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
	actualDaemonVersion := res.Header.Get("x-kastela-version")
	if semver.MajorMinor(actualDaemonVersion) == expectedKastelaVersion || actualDaemonVersion == "v0.0.0" {
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
	} else {
		err = fmt.Errorf(`kastela server version mismatch, expected: %s.x, actual: %s`, expectedKastelaVersion, actualDaemonVersion)
	}
	return
}

// Store batch vault data on the server.
//
//	// prepare input data
//	var vaultData []any
//	vaultData = append(vaultData, map[string]any{"name": "jhon doe", "secret" : "12345678"})
//	vaultData = append(vaultData, map[string]any{"name": "jane doe", "secret" : "12345678"})
//	// store data to vault
//	client.VaultStore("yourVaultId", vaultData)
func (c *Client) VaultStore(vaultId string, data []any) (ids []string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"data": data}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/store`, c.kastelaUrl, vaultPath, vaultId)); err != nil {
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
	idsAny := body["ids"].([]any)
	ids = make([]string, len(idsAny))
	for i, v := range idsAny {
		ids[i] = v.(string)
	}
	return
}

// Search vault data by indexed column.
//
//	// search "jhon doe" data
//	client.VaultFetch("yourVaultId", "jhon doe", nil)
func (c *Client) VaultFetch(vaultId string, search string, params *FetchVaultParams) (ids []string, err error) {
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s`, c.kastelaUrl, vaultPath, vaultId)); err != nil {
		return
	}
	query := serverUrl.Query()
	query.Set("search", search)
	if params != nil {
		if params.Size > 0 {
			query.Set("size", fmt.Sprint(params.Size))
		}
		if len(params.After) > 0 {
			query.Set("after", params.After)
		}
	}
	serverUrl.RawQuery = query.Encode()
	var resBody []byte
	if resBody, err = c.request("GET", serverUrl, nil); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	idsAny := body["ids"].([]any)
	ids = make([]string, len(idsAny))
	for i, v := range idsAny {
		ids[i] = v.(string)
	}
	return
}

// Get batch vault data by vault data ids.
//
//	client.VaultGet("yourVaultId", []string{"d2657324-59f3-4bd4-92b0-c7f5e5ef7269", "331787a5-8930-4167-828f-7e783aeb158c"})
func (c *Client) VaultGet(vaultId string, ids []string) (data []any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"ids": ids}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/get`, c.kastelaUrl, vaultPath, vaultId)); err != nil {
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
	data = body["data"].([]any)
	return
}

// Update vault data by vault data id.
//
// 	client.VaultUpdate("yourVaultId", "331787a5-8930-4167-828f-7e783aeb158c", map[string]any{"name": "jane d'arc", "secret" : "12345678"})

func (c *Client) VaultUpdate(vaultId string, token string, data any) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(data); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/%s`, c.kastelaUrl, vaultPath, vaultId, token)); err != nil {
		return
	}
	if _, err = c.request("PUT", serverUrl, reqBody); err != nil {
		return
	}
	return
}

// Remove vault data by vault data id.
//
//	client.VaultDelete("yourVaultId", "331787a5-8930-4167-828f-7e783aeb158c")
func (c *Client) VaultDelete(vaultId string, token string) (err error) {
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/%s`, c.kastelaUrl, vaultPath, vaultId, token)); err != nil {
		return
	}
	if _, err = c.request("DELETE", serverUrl, nil); err != nil {
		return
	}
	return
}

// Encrypt data protection by protection data ids, which can be used after storing data or updating data.
//
//	// protect data with id 1,2,3,4,5
//	client.ProtectionSeal("yourProtectionId", []any{1,2,3,4,5})
func (c *Client) ProtectionSeal(protectionId string, ids []any) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"ids": ids}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/seal`, c.kastelaUrl, protectionPath, protectionId)); err != nil {
		return
	}
	if _, err = c.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	return
}

// Decrypt data protection by protection data ids.
//
//	// decript data with id 1,2,3,4,5
//	client.ProtectionOpen("yourProtectionId", []any{1,2,3,4,5})
func (c *Client) ProtectionOpen(protectionId string, ids []any) (data []any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"ids": ids}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/open`, c.kastelaUrl, protectionPath, protectionId)); err != nil {
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
	data = body["data"].([]any)
	return
}

// Begin secure channel.
//
//	// begin secure channel
//	client.SecureChannelBegin("yourProtectionId", "yourClientPublicKey", 5)
func (c *Client) SecureChannelBegin(protectionId string, clientPublicKey string, ttl int) (id string, serverPublicKey string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{
		"protection_id":     protectionId,
		"client_public_key": clientPublicKey,
		"ttl":               ttl,
	}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/begin`, c.kastelaUrl, secureChannelPath)); err != nil {
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
	id = body["id"].(string)
	serverPublicKey = body["server_public_key"].(string)
	return
}

// Commit secure channel.
//
//	// commit secure channel
//	client.SecureChannelCommit("yourSecureChannelId")
func (c *Client) SecureChannelCommit(secureChannelId string) (err error) {
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/commit`, c.kastelaUrl, secureChannelPath, secureChannelId)); err != nil {
		return
	}
	if _, err = c.request("POST", serverUrl, nil); err != nil {
		return
	}
	return
}

// Proxying request.
//
//	 // call request
//		client.PrivacyProxyRequest("json", "https://enskbwhbhec7l.x.pipedream.net/:_phone/:_salary", "post", kastela.PrivacyProxyCommon{
//			Protections: map[string]string{
//				"_email": "124edec8-530e-4fd2-a04b-d4dc21ce625a",
//				"_phone": "9f53aa3b-7214-436d-af9b-d2952be9f0c4",
//			}, Vaults: map[string][]string{
//				"_salary": {
//					"c5f9236d-aea0-46a5-a2fe-fb75c0596c87",
//					"salary",
//				},
//			},
//		}, &kastela.PrivacyProxyOptions{
//			Headers: map[string]any{
//				"_email": "1",
//			},
//			Params: map[string]any{
//				"_phone":  "1",
//				"_salary": "01GQEATT1Q3NKKDC3A2JSMN7ZJ",
//			},
//			Body: map[string]any{
//				"name":    "jhon daeng",
//				"_email":  "1",
//				"_phone":  "1",
//				"_salary": "01GQEATT1Q3NKKDC3A2JSMN7ZJ",
//			},
//			Query: map[string]any{
//				"id":     "123456789",
//				"_email": "1",
//			},
//		})
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
