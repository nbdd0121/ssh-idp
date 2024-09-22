# SSH IdP

An JWT identity provider based on SSH.

`ssh-idp` runs as a SSH server.
When a SSH client make connection to `ssh-idp`, it checks the public key against a preconfigured list of known identities.
If an entry matches, the identity is confirmed, and a JWT token is signed.

Currently only ED25519 SSH keys are supported.

## Configuration

These options are required for the `ssh-idp` server:

* JWT signing key

  Currently `ssh-idp` only supports the mostly commonly accepted RS256 algorithm, and therefore this must be a RSA private key.

  This can be generated using `openssl`:

  ```sh
  openssl rsa -in sign.key -pubout -out sign.pub
  ```

* JWT issuer

  This identifies who issues the JWT.
  This is passed directly to the JWT standard `iss` claim.

* SSH host key

  Host key used by SSH server.
  Currently only ED25519 keys are supported, and should be unencrypted.

  This can be generated using `ssh-keygen`:

  ```sh
  ssh-keygen -t ed25519 -f ssh_host_key
  ```

  For best security practice, pre-fill client's known_hosts with the public key.

* Known identities

  A mapping of identity to public keys.
  This is stored using SSH known hosts format.

  ```
  my.host.name ssh-ed25519 AAAA1234...
  another.host ssh-ed25519 AAAA5678...
  ```

  This means that when `AAAA1234...` is used to access `ssh-idp`, the JWT signed will include `my.host.name` as the subject claim.

  When multiple identities are configured for the same public key, the first matching entry serves as the subject claim, and a `sans` custom claim is filled with all matching identites.

  The known hosts file is reloaded for every JWT signing request, so there is no need to restart server if content changed.

Example:
```sh
ssh-idp --jwt-signing-key sign.key --jwt-issuer https://example.com --ssh-host-key ssh_host_key --known-hosts known_hosts
```

Additional, SSH listening address and ports can be configured using `--ssh-addr` and `--ssh-port`, and JWT valid duratiton can be configured with `--jwt-valid-duration`.

## Usage

To use the SSH IdP server to obtain a JWT token, one can simply use SSH to do it:
```sh
ssh idp-server -p 2222 <audience>
```

Audience is required, and this should be reflecting the party that is expecting this JWT token.

Example:
```console
$ ssh idp-server -p 2222 https://example.com
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc...
```

## Use cases

SSH IdP can be used both for issuing tokens for user or machine identity.

For user identity, add user's `~/.ssh/id_ed25519.pub` into the known hosts file:
```
john.doe@example.com ssh-ed25519 AAAA...
```

Then they can access using `ssh` as mentioned in the usage section to obtain the token.

For machine identity, add machine's `/etc/ssh/ssh_host_ed25519_key.pub` to the known hosts file.
You can do this remotely by using `ssh-keyscan`:
```sh
ssh-keyscan -t ed25519 my-server
```

And then add to known hosts file:
```sh
my-machine.example.com ssh-ed25519 AAAA...
```

The *root* user on the machine then can use SSH to obtain a token identifying the machine:
```sh
ssh -o IdentitiesOnly=yes -i /etc/ssh/ssh_host_ed25519_key idp-server -p 2222 <audience>
```

Note that we're now using the host key as SSH identity so it identifies the host instead of the root user.
`-o IdentitiesOnly=yes` is optional, but can be useful if the root user has SSH keys configured.
