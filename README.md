# Keycloak sample using Golang

The proposal of this project is describing how to authenticate and authorize an
application using Keycloak and Golang.

## Prerequisites

* [Golang](https://go.dev/) 1.18 or higher;
* [Docker](https://www.docker.com/) (or a standalone [Keycloak](https://go.dev/) version 21)

## Setup

### Keycloak environment

Start the Keycloak environment set at `docker-compose.yaml`:

``` shell
docker-compose up --build
```

Create the realm, client and default user:
* Login at Keyckoak console following this link: http://localhost:8080;
* Use `admin` as username and `Pa55w0rd` as password;
* Create a new realm: Once you have logged in, you will see a dropdown menu in the top left corner of the page.
Click on it and select _Add Realm_ to create a new one;
* Fill the Realm Name field with `Playground` and click in _Create_ button;
* In the left sidebar menu, click in _Clients_ and _Create client_ button;
* Use `my-client` as _Client ID_ value and click in _Next_;
* Keep the currently values and click in _Next_ again;
* Fill the _Root URL_ field with `http://localhost:9090` and click in _Save_ button;
* Under the _Settings_ tab, set the _Valid redirect URIs_ as `http://localhost:9090/auth/callback`;
* In the left sidebar menu, click in _Users_ and _Add user_ button;
* Choose some _Username_ and click in _Create_ button;
* At _Credentials_ tab, click in _Set password_ button, fill the _Password_ and _Password confirmation_ fields
* Set _Temporary_ as `off` as click in _Save_ button.

### Running the application

Run the `api.go`:
```shell
go run cmd/api/api.go
```

Follow this link and proceed with login steps: [http://localhost:8080](http://localhost:8080/).
Once you're logged in successfully, the API will return the `access_token` and other information.
Now you can access an authenticated endpoint `/details` using this token provided:

```shell
curl --location --request GET 'localhost:9090/details' \
--header "Authorization: Bearer ${YOUR_TOKEN_HERE}"
```