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

const expectedKastelaVersion string = "v0.0"
const vaultPath string = "api/vault"
const protectionPath string = "api/protection"

type Client struct {
	kastelaUrl string
	client     *http.Client
}

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

func (k *Client) request(method string, serverUrl *url.URL, data []byte) (resBody []byte, err error) {
	reqBody := bytes.NewBuffer(data)
	var req *http.Request
	if req, err = http.NewRequest(method, serverUrl.String(), reqBody); err != nil {
		return
	}
	var res *http.Response
	if res, err = k.client.Do(req); err != nil {
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

func (k *Client) VaultStore(vaultId string, data []any) (ids []string, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"data": data}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/store`, k.kastelaUrl, vaultPath, vaultId)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = k.request("POST", serverUrl, reqBody); err != nil {
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

func (k *Client) VaultFetch(vaultId string, search string, params *FetchVaultParams) (ids []string, err error) {
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s`, k.kastelaUrl, vaultPath, vaultId)); err != nil {
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
	if resBody, err = k.request("GET", serverUrl, nil); err != nil {
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

func (k *Client) VaultGet(vaultId string, ids []string) (data []any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"ids": ids}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/get`, k.kastelaUrl, vaultPath, vaultId)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = k.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	data = body["data"].([]any)
	return
}

func (k *Client) VaultUpdate(vaultId string, token string, data any) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(data); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/%s`, k.kastelaUrl, vaultPath, vaultId, token)); err != nil {
		return
	}
	if _, err = k.request("PUT", serverUrl, reqBody); err != nil {
		return
	}
	return
}

func (k *Client) VaultDelete(vaultId string, token string) (err error) {
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/%s`, k.kastelaUrl, vaultPath, vaultId, token)); err != nil {
		return
	}
	if _, err = k.request("DELETE", serverUrl, nil); err != nil {
		return
	}
	return
}

func (k *Client) ProtectionSeal(protectionId string, ids []any) (err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"ids": ids}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/seal`, k.kastelaUrl, protectionPath, protectionId)); err != nil {
		return
	}
	if _, err = k.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	return
}

func (k *Client) ProtectionOpen(protectionId string, ids []any) (data []any, err error) {
	var reqBody []byte
	if reqBody, err = json.Marshal(map[string]any{"ids": ids}); err != nil {
		return
	}
	var serverUrl *url.URL
	if serverUrl, err = url.Parse(fmt.Sprintf(`%s/%s/%s/open`, k.kastelaUrl, protectionPath, protectionId)); err != nil {
		return
	}
	var resBody []byte
	if resBody, err = k.request("POST", serverUrl, reqBody); err != nil {
		return
	}
	var body map[string]any
	if err = json.Unmarshal(resBody, &body); err != nil {
		return
	}
	data = body["data"].([]any)
	return
}
