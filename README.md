# sub-store-convert

**sub-store-convert** runs the node conversion logic from [Sub-Store](https://github.com/sub-store-org/Sub-Store) as a standalone library, CLI, HTTP service, and Cloudflare Worker.

It can convert remote subscription links into formats used by clients such as Surge, Quantumult X, Loon, Clash/Mihomo, Stash, Shadowrocket, Surfboard, sing-box, Egern, and more.

## Features

- Standalone conversion core extracted from Sub-Store.
- HTTP API compatible with the common `subconverter` style: `/sub?target=...&url=...`.
- Local server support with Node.js or Bun.
- CLI for quick one-off conversions.
- Cloudflare Workers and Docker deployment support.
- Multiple subscription URLs supported by separating them with `|`.

## Packages

This repository is a pnpm workspace with three packages:

| Package | Description |
| --- | --- |
| `@sub-store-convert/core` | Core conversion library. Exports `convert()` and lower-level parser/producer helpers. |
| `@sub-store-convert/app` | Hono HTTP app for local server and Cloudflare Workers. |
| `@sub-store-convert/cli` | Interactive CLI wrapper around the core converter. |

## Requirements

- Node.js 22 or later is recommended.
- pnpm is used for workspace dependency management.
- Bun is optional, but used by the Docker runtime and supported by the local server script.
- Wrangler is required only for Cloudflare Workers deployment.

## Installation

Clone the repository with its Sub-Store submodule:

```bash
git clone --recursive git@github.com:TBXark/sub-store-convert.git
cd sub-store-convert
pnpm install
```

If you cloned without `--recursive`, initialize the submodule before installing or building:

```bash
git submodule update --init --recursive
pnpm install
```

## Quick Start

Build the core package first:

```bash
pnpm run build:core
```

Start the HTTP service locally:

```bash
pnpm run start
```

The service listens on `http://localhost:3000` by default. Use `PORT` to change the port:

```bash
PORT=8080 pnpm run start
```

Convert a subscription through the HTTP API:

```bash
curl "http://localhost:3000/sub?target=surge&url=https%3A%2F%2Fexample.com%2Fsubscription"
```

## Usage

### HTTP API

```text
GET /sub?target=<target>&url=<subscription-url>
```

Required query parameters:

| Parameter | Description |
| --- | --- |
| `target` | Output format, for example `surge`, `qx`, `mihomo`, `sing-box`, or `json`. |
| `url` | Remote subscription URL. Multiple URLs can be joined with `|`. |

Additional query parameters are passed to the converter as options. String values of `true`, `false`, and numeric values are converted to booleans or numbers automatically.

Example with multiple subscription URLs:

```bash
curl "http://localhost:3000/sub?target=mihomo&url=https%3A%2F%2Fexample.com%2Fa%7Chttps%3A%2F%2Fexample.com%2Fb"
```

### CLI

Run the workspace CLI:

```bash
pnpm run cli https://example.com/subscription
```

The CLI prompts for the target format. Press Enter to use the default target, `surge`.

### Core API

Use the core package directly from JavaScript:

```js
import { convert } from '@sub-store-convert/core'

const output = await convert('https://example.com/subscription', 'surge', {
  udp: true,
})

console.log(output)
```

## Supported Targets

Common target names include:

| Target | Aliases |
| --- | --- |
| Quantumult X | `qx`, `QX`, `QuantumultX` |
| Surge | `surge`, `Surge`, `SurgeMac` |
| Loon | `Loon` |
| Clash | `Clash` |
| Mihomo / Clash.Meta | `meta`, `clashmeta`, `clash.meta`, `Clash.Meta`, `ClashMeta`, `mihomo`, `Mihomo` |
| URI | `uri`, `URI` |
| V2Ray | `v2`, `v2ray`, `V2Ray` |
| JSON | `json`, `JSON` |
| Stash | `stash`, `Stash` |
| Shadowrocket | `shadowrocket`, `Shadowrocket`, `ShadowRocket` |
| Surfboard | `surfboard`, `Surfboard` |
| sing-box | `singbox`, `sing-box` |
| Egern | `egern`, `Egern` |

Supported input formats are inherited from Sub-Store parsers, including common URI formats and client formats such as Clash, Surge, Loon, and Quantumult X.

## Scripts

| Command | Description |
| --- | --- |
| `pnpm run build:core` | Build `@sub-store-convert/core`. |
| `pnpm run build:app` | Build the Cloudflare Worker bundle. |
| `pnpm run build:docker` | Build the Docker image `ghcr.io/tbxark/sub-store-convert:latest`. |
| `pnpm run start` | Start the HTTP service with Bun, falling back to Node.js. |
| `pnpm run start:bun` | Start the HTTP service with Bun. |
| `pnpm run start:node` | Start the HTTP service with Node.js. |
| `pnpm run start:docker` | Run the published Docker image on port `3000`. |
| `pnpm run cli` | Run the CLI package. |
| `pnpm run clean` | Remove workspace dependencies and build output. |
| `TAG=<version> pnpm run update:vendor` | Update the vendored Sub-Store submodule and package versions. |
| `pnpm run publish` | Publish the built core package. |

## Deployment

### Cloudflare Workers

The Worker configuration lives in `packages/app/wrangler.jsonc`.

Build the Worker bundle:

```bash
pnpm run build:app
```

Deploy with Wrangler:

```bash
pnpm --filter @sub-store-convert/app worker:deploy
```

### Docker

Build the Docker image locally:

```bash
pnpm run build:docker
```

Run the image:

```bash
docker run --rm --name sub-store-convert -p 3000:3000 ghcr.io/tbxark/sub-store-convert:latest
```

Or use the workspace shortcut:

```bash
pnpm run start:docker
```

## Vendor Update

Sub-Store is vendored as a git submodule at `packages/core/src/vendors/Sub-Store`.

To update it to a specific tag or version:

```bash
TAG=<version> pnpm run update:vendor
```

## License

**sub-store-convert** is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
