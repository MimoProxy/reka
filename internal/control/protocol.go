// Package control serves Reka's native control API over a Unix domain
// socket or a Windows named pipe, accepting only the current user (or an
// explicitly configured owner). The protocol, wire types and the client
// live in internal/api; this package adds the server and session handling.
package control

import "github.com/MimoProxy/reka/internal/api"

// Protocol names used by the server and its tests.
type (
	Request     = api.Request
	Response    = api.Response
	Message     = api.Message
	HelloParams = api.HelloParams
	HelloResult = api.HelloResult
	Status      = api.Status
	Client      = api.Client
)

const (
	APIVersion        = api.APIVersion
	MaxFrame          = api.MaxFrame
	CodeHelloRequired = api.CodeHelloRequired
	CodeVersion       = api.CodeVersion
	CodeUnknownMethod = api.CodeUnknownMethod
	CodeInternal      = api.CodeInternal
	CodeDenied        = api.CodeDenied
)

var (
	WriteFrame       = api.WriteFrame
	ReadFrame        = api.ReadFrame
	ErrFrameTooLarge = api.ErrFrameTooLarge
	ErrClosed        = api.ErrClosed
	Connect          = api.Connect
	NewClient        = api.NewClient
	Dial             = api.Dial
	DefaultAddress   = api.DefaultAddress
)
