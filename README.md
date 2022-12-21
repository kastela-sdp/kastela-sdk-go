# Kastela SDK for Go

Credential is required when using the SDK, download it on the entities page.

Usage Examples :

```go
const protectionId = "28e61e5f-d575-49db-8dfb-1c5063213a76"

client := kastela.NewClient("https://server.kastela.org", "./credentials/ca.crt", "./credentials/client.crt", "./credentials/client.key")

values, err := client.ProtectionOpen(protectionId, []int{1, 2, 3, 4})
if err != nil {
 return nil, err
} else {
 fmt.Println(values); // should print raw data form id 1,2,3,4
}
```
