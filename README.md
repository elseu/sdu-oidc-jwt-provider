# OIDC JWT Provider

> Provide JWTs for API access from an OpenID Connect backend

TODO

## Table of Contents <!-- omit in toc -->

- [Background](#background)
- [Install](#install)
  - [For development](#for-development)
- [Usage](#usage)
- [Configuration](#configuration)
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

If you want to use Redis you can setup up a docker-compose.yml file and then run docker-compose up -d to start Redis.
```yml
version: "3"
services:
    redis:
        image: "redis"
        ports:
            - 6379:6379

```

## Usage

TODO

## Configuration

TODO

You can configure the services through these environment variables:

| Variable       | Usage                                                                                                     |
| -------------- | --------------------------------------------------------------------------------------------------------- |
| `LOG_REQUESTS` | If set to `true` or `1`, all HTTP requests are logged to stdout.                                          |
| `PORT`         | Port number to run the service on. Defaults to `3000`. The the Docker image sets this to `80` by default. | ` |

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
