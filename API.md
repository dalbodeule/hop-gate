# HopGate API

## Admin API

Admin endpoints are served under `/api/v1/admin/` on `HOP_SERVER_DOMAIN` and
require `Authorization: Bearer $HOP_ADMIN_API_KEY`.

- `POST /api/v1/admin/domains/register`
  - Request: `{"domain":"app.example.com","memo":"optional"}`
  - Response includes the generated `client_api_key`.
- `POST /api/v1/admin/domains/unregister`
  - Request: `{"domain":"app.example.com","client_api_key":"..."}`

## Tunnel Configuration

The server listens for client tunnels on `HOP_SERVER_TUNNEL_LISTEN`, defaulting
to `:7443`. The client connects to that address with
`HOP_CLIENT_SERVER_ADDR`. The client only needs an outbound TCP connection.

Required client settings are `HOP_CLIENT_SERVER_ADDR`, `HOP_CLIENT_DOMAIN`,
`HOP_CLIENT_API_KEY`, `HOP_CLIENT_LOCAL_TARGET`, and `HOP_CLIENT_DEBUG`.
