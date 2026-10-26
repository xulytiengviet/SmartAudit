# SmartAudit Verified Solidity Web

A read-only **preliminary review** of publicly verified Solidity source from Etherscan or Sourcify. Not a guarantee of security, not an exploitability proof, not an automated full audit.

## Deploy

1. Deploy `worker/` from repo root with Wrangler: `cd worker && npx wrangler deploy`. Install the Wrangler CLI via npx if prompted.
2. Recommended: set Etherscan API v2 key as a Worker secret: `npx wrangler secret put ETHERSCAN_API_KEY`. Without the key, Sourcify is used when a verified match is available.
3. Publish the `web/` directory as a static site (GitHub Pages / Cloudflare Pages), **or** visit `https://xulytiengviet.github.io/SmartAudit/web/` if GitHub Pages is configured at repository root.
4. Open the web page, expand **Cài đặt API phân tích**, paste your Worker HTTPS origin. Paste a verified `https://etherscan.io/address/0x...` URL. A frontend-only GitHub Pages site cannot securely store an Etherscan key.
5. Optional: set `FRONTEND_ORIGIN` in Wrangler vars to your Pages origin (only one origin is supported with this simple CORS implementation). Add Cloudflare rate limiting and quotas before public high-volume usage.

## Coverage

- Read-only URL input; Ethereum mainnet and specified Etherscan testnets.
- Verified Solidity sources (single and multi-file), compiler and proxy metadata when available.
- Version-aware preliminary rules for tx.origin, delegatecall, low-level ETH calls, timestamp, blockhash, unchecked blocks, assembly, ecrecover, abi.encodePacked, send/transfer, selfdestruct and pre-0.8 overflow review.
- Locations, severity, suggestions, filter, and JSON export.
- Limits: no AST, no verified compiler build, no dependency resolution, no transaction tracing, no interprocedural dataflow, no symbolic execution, no Slither or fuzzing in this web MVP. Many findings can be false positives; dangerous code can go unreported.
- Proxy implementations require a separate scan using the implementation address. Metadata does not guarantee full implementation-resolution.
- This product does not access wallets, keys, funds or send transactions.

## Full audit evolution

For deeper results, add a sandboxed backend job pinned to metadata exact solc with `solc-select`, run Slither/Mythril and tests with resource/time limits, normalize tool findings, and analyze upgradeable proxy storage/implementation. Do not try to ship full symbolic execution in a browser. Tool coverage across all historical Solidity releases depends on compatibility, compiler availability and EVM fork; fail explicitly for unsupported versions.
