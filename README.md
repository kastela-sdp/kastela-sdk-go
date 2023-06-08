# Kastela SDK for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/kastela-sdp/kastela-sdk-go.svg)](https://pkg.go.dev/github.com/kastela-sdp/kastela-sdk-go)

## Installation

```bash
go get github.com/kastela-sdp/kastela-sdk-go
```

## Usage

```go
package main

import (
  "fmt"
  "log"

  "github.com/kastela-sdp/kastela-sdk-go"
)

func main() {
  client := kastela.NewClient("https://127.0.0.1:3100", "./ca.crt", "./client.crt", "./client.key")
  
  data, err := client.ProtectionOpen([]*kastela.ProtectionOpenInput{
    {
      ProtectionID: "your-protection-id",
      Tokens: []any{"foo", "bar", "baz"},
    },
  })
  if err != nil {
    log.Fatalln(err)
  }
  
  fmt.Println(data)
}
```

## Reference

- [Documentation](https://pkg.go.dev/github.com/kastela-sdp/kastela-sdk-go)
