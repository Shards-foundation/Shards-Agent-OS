# Private HTTPS for the Oracle staging origin

The browser uses `https://agentos-stage.shardsinc.co.uk`. The staging Worker verifies Access, signs the actor and fetches `https://agentos-origin-stage.shardsinc.co.uk` through `AGENT_OS_ORIGIN`. The VPC Service selects the staging tunnel and dials **127.0.0.1:18443 in the connector's network namespace**. The fetch hostname supplies the TLS SNI and HTTP Host. The configured IP and HTTPS port supply the destination. This IP-based service requires no origin DNS record, resolver, hostname route, OCI ingress rule or tunnel configuration change. Every replica registered to that tunnel must reach the same intended endpoint on its own loopback. Four connections can belong to one connector. [VPC routing and TLS](https://developers.cloudflare.com/workers-vpc/configuration/vpc-services/) · [Tunnel prerequisites](https://developers.cloudflare.com/workers-vpc/configuration/tunnel/)

A dedicated unprivileged Apache process uses only Ubuntu's `apache2-bin` and the checked-in standalone configuration. It forwards the four routes accepted by the Worker to `127.0.0.1:12026`. Apache preserves the Worker-supplied `X-Shards-Actor`, `X-Shards-Assertion`, `X-Forwarded-Host`, browser Origin, session cookie, query, body, upstream Location and Set-Cookie fields. The upstream HTTP Host is the loopback application. The kernel at 18765 has no route here. The TLS unit has no dependency that starts the web service, kernel or tunnel.

## Oracle operator

Use the existing Termius administrator session and the reviewed PR commit. From `/opt/shards-agent-stage/source`, define this shortcut once per shell.

```sh
https_stage() { sudo /usr/bin/python3 -I /opt/shards-agent-stage/source/deploy/oracle/https/manage.py "$@"; }
```

1. Run the **read-only** checks. Expect a supported connector with QUIC registration on host loopback, both application units loaded and inactive, both application ports unused, and port 18443 free or owned by the matching TLS unit. The script checks the running connector binary and examines only its current invocation's registration messages. It prints no tunnel arguments or journal lines.

   ```sh
   https_stage preflight
   ```

2. Create the on-host P-256 TLS key and public CSR. Repeating the command reuses the key and CSR. Copy only the block from `BEGIN CERTIFICATE REQUEST` through `END CERTIFICATE REQUEST` to the certificate issuer. All TLS artifacts stay under `/etc/shards-stage-https`. The private key is root-owned 0600 and delivered to the dedicated unit through systemd credentials.

   ```sh
   https_stage csr
   ```

   The proposed certificate is a Cloudflare Origin CA **ECC** certificate for the single exact SAN `agentos-origin-stage.shardsinc.co.uk`. An authorised issuer can use the existing CSR via `POST /certificates`, specifying `request_type=origin-ecc`, that one hostname and a supported lifetime such as 90 days. Its token needs the zone's **SSL and Certificates Edit** permission. This is a new origin certificate, separate from the existing Access application and signing authorities. Record the expiry for renewal. [Origin CA issuance and public roots](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)

3. Once the issuer supplies the public certificate, install the binary if preflight reported it missing. Review the package plan and stop on unrelated removals, upgrades or service changes. The binary package has no default site or service. The full `apache2` package is unnecessary. [Ubuntu ARM64 package contents](https://packages.ubuntu.com/noble/arm64/apache2-bin/filelist)

   ```sh
   test -x /usr/sbin/apache2 || sudo apt-get install --no-install-recommends --no-upgrade apache2-bin
   ```

4. Install and verify. Paste only the signed public leaf PEM when prompted. The helper checks the pinned Cloudflare ECC root, certificate time, hostname, single SAN and key match before starting the dedicated TLS unit. It enables that unit only after verification. An identical retry reuses the installed certificate. The expected final line is `HTTPS verified: full chain and hostname, outside mount 404, stopped origin 503.` from the separate verify command.

   ```sh
   https_stage install && https_stage verify
   ```

**Independent check while Agent OS is stopped.** Run this from the reviewed checkout. Curl makes a loopback connection, sends the private SNI/Host, verifies the named certificate with the public CA, and displays only status and the terminator's response marker. Expect `404 1` then `503 1`. The marker distinguishes a response from this terminator from the staging Worker's unbound-service 503. Port 18443 must have exactly one loopback listener. The other two ports must have none.

```sh
for path in / /agent-os/; do
  curl --noproxy '*' --silent --show-error --connect-timeout 4 --max-time 8 \
    --cacert deploy/oracle/https/origin-ca-ecc.pem \
    --connect-to agentos-origin-stage.shardsinc.co.uk:443:127.0.0.1:18443 \
    -o /dev/null -w '%{http_code} %header{x-shards-stage-tls}\n' \
    "https://agentos-origin-stage.shardsinc.co.uk$path" || break
done
ss -H -ltn '( sport = :18443 or sport = :12026 or sport = :18765 )'
```

**Stop conditions.** Stop on a host/namespace mismatch, competing listener or unit, active kernel or web service, missing current QUIC evidence, cloudflared older than 2025.7.0, unexpected tunnel replica, certificate error, or an unexpected status or marker. Keep full TLS verification. Investigate locally without sharing tunnel command lines, raw journals, credentials or private keys.

**Rollback.** This disables, stops and removes only the matching dedicated HTTPS unit and reloads systemd. Configuration, certificate, CSR and host key remain available for an identical reinstall. Confirm port 18443 is closed and the tunnel remains active.

```sh
https_stage rollback && ss -H -ltn 'sport = :18443' && systemctl is-active shards-stage-tunnel.service
```

## Cloudflare handoff after Oracle verification

These are proposed operations requiring separate staging authorisation. First confirm the existing tunnel UUID, its connector placement and QUIC transport, the intended staging Worker/version and its existing Access bindings. Reuse a matching service if one has since been created. Stop on any same-name configuration mismatch.

1. With **Connectivity Directory Admin**, create one HTTP-type service using `POST /accounts/{account_id}/connectivity/directory/services`. Supply only the HTTPS port. Read the resulting service back and verify the tunnel, IP, exclusive HTTPS port and TLS mode. The built-in Cloudflare Origin CA trust needs no CA upload or client key. [Service creation API](https://developers.cloudflare.com/api/resources/connectivity/subresources/directory/subresources/services/methods/create/)

   ```json
   {
     "name": "shards-stage-agent-os-https",
     "type": "http",
     "host": {"ipv4": "127.0.0.1", "network": {"tunnel_id": "<existing staging tunnel UUID>"}},
     "https_port": 18443,
     "tls_settings": {"cert_verification_mode": "verify_full"}
   }
   ```

2. With **Connectivity Directory Bind** (or Admin) and staging Worker edit authority, bind that service ID as `AGENT_OS_ORIGIN` on the **existing staging Worker**. Set `ORIGIN_BASE_URL=https://agentos-origin-stage.shardsinc.co.uk`. Preserve the deployed Worker code, other bindings, hostname and Access audience. Apply these through a reviewed staging version change. The repository Wrangler template is an incomplete inventory of the deployed Worker. [Binding schema and roles](https://developers.cloudflare.com/workers-vpc/configuration/vpc-services/#workers-binding-configuration)

3. The staging Worker still requires `ORIGIN_ASSERTION_SECRET` matching the origin's `SHARDS_EDGE_ASSERTION_SECRET`. Its custodian must supply it through authorised secret tooling. Keep it out of chat, source, arguments and logs. Worker binding changes and secret provisioning are independent of TLS installation.

4. Once those gates are satisfied, use an authorised Access session for `GET https://agentos-stage.shardsinc.co.uk/agent-os/`. While the web application remains stopped, **503 with `X-Shards-Stage-TLS: 1`** demonstrates that the reviewed Worker reached the verified private endpoint. An anonymous Access redirect, an unmarked 503 or a local curl result cannot establish this. Browser-to-application authentication and signed execution belong to later acceptance.
