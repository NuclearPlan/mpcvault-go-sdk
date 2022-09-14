# Go MPCVault

[![Go Reference](https://pkg.go.dev/badge/github.com/mpcvault/mpcvault-go-sdk)](https://pkg.go.dev/github.com/mpcvault/mpcvault-go-sdk)
[![Go](https://github.com/mpcvault/mpcvault-go-sdk/actions/workflows/go.yml/badge.svg)](https://github.com/mpcvault/mpcvault-go-sdk/actions/workflows/go.yml)

The official Go library for the MPCVault API.


# Installation

Make sure your project is using Go Modules (it will have a `go.mod` file in its root if it already is):

```bash
go mod init
```

Then, reference mpcvault-go-sdk in a Go program with import:

```go
import (
	"github.com/mpcvault/mpcvault-go-sdk"
)
```

Alternatively, you can also explicitly go get the package into a project:

```bash
go get -u "github.com/mpcvault/mpcvault-go-sdk"
```

# Documentation

For a comprehensive list of examples, check out the [API
documentation].

# Usage

## Setup the client

```go
// Initialization variables
var apiKey = "[API Key]"
var privateKey = "[OPENSSH PRIVATE KEY]"

// Create an SDK instance
mpcvault := &sdk.API{}
err := mpcvault.SetUp(apiKey, privateKey, "")
```


[API documentation]: https://docs.mpcvault.com
