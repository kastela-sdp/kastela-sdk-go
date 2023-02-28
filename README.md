# Kastela SDK for Go

Credential is required when using the SDK, download it on the entities page.

Usage Examples :

```go
client := kastela.NewClient("https://server.kastela.org", "./ca.crt", "./client.crt", "./client.key")

data, err := client.protectionOpen([]*ProtectionOpenInput{ProtectionId: "your-protection-id", Tokens: []any{a, b, c, d, e}})
if err != nil {
  log.Fatalln(err)
}

fmt.Println("data", data)
```
