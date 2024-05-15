# OIDC JWT Provider

> Provide JWTs for API access from an OpenID Connect backend

TODO

## Table of Contents <!-- omit in toc -->

- [Background](#background)
- [Install](#install)
  - [For development](#for-development)
- [Usage](#usage)
- [Configuration](#configuration)
- [FAQ](#faq)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Background

Many modern frontend websites:

-   Run in the browser;
-   Let users authenticate with OpenID Connect;
-   Connect to backend APIs;
-   Authenticate with those APIs through the user's access token.

This requires that the backend services consume and validate access tokens in a uniform and safe way. OIDC JWT Provider helps generate JWT tokens for API access based on the user's session with an OpenID Connect IdP.

## Install

The best way to run this service is through Docker: `docker pull ghcr.io/elseu/sdu-oidc-jwt-provider:latest`.

### For development

If you want to develop OIDC JWT Provider, run:

```
npm install
npm run dev # to run nodemon and reload when you change code
npm run start # to run in normal mode
```

If you want to use Redis as session storage you can use the docker-compose.yml file and then run `docker-compose up -d` to start Redis.
## Usage

TODO

## Configuration

TODO

You can configure the services through these environment variables:

| Variable         | Usage                                                                                                     |
| ---------------- | --------------------------------------------------------------------------------------------------------- |
| `LOG_REQUESTS`   | If set to `true` or `1`, all HTTP requests are logged to stdout.                                          |
| `PORT`           | Port number to run the service on. Defaults to `3000`. The the Docker image sets this to `80` by default. | ` |
| `SESSION_EXPIRE_ON_BROWSER_RESTART` | If set to `true` or `1`, the session will be only valid in a browser session because the cookies will be saved as a session cookie |


## FAQ
### How to use Redis for Session Storage?
To use Redis for session management you can turn it on by setting `SESSION_STORAGE=redis` in your .env file.

To start Redis locally using docker run `docker run --name oidc-jwt-provider-redis -d redis` in your terminal.
After this you can set the Redis url in the .env file under `REDIS_URL=`.
The default Redis url is set to `redis://localhost`.

To use Redis in Production please contact your DevOps department.

### How to generate a private signing key?
You can generate a private signing key using OpenSSL or a similar service.
Example: 
```
openssl genpkey -algorithm RSA -aes-256-cbc -outform PEM -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```
For explanation of the options check the [OpenSSL documentation](https://www.openssl.org/docs/man1.1.1/man1/openssl-genpkey.html#KEY-GENERATION-OPTIONS)


#### Alternative way to generate a key
Run in terminal:
```brew install mkcert`

Then type:
```mkcert -install```

Followed by:
```mkcert yourSiteName```

Replace `yourSiteName` with any name of your website. For example: download-site-acc

This will generate 2 files: `{yourSiteName}.pem` and `{yourSiteName}-key.pem`.

Now base64 encode the file and you have your base64 encoded signing key.
```cat `{yourSiteName}-key.pem | base64```

## Maintainers

-   [Sebastiaan Besselsen](https://github.com/sbesselsen) (Sdu)

## Contributing

Please create a branch named `feature/X` or `bugfix/X` from `master`. When you are done, send a PR to Sebastiaan Besselsen.

## License

Licensed under the MIT License.

Copyright 2020 Sdu Uitgevers.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
