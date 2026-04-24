# Authentication

This document describes the authentication methods supported by this API.

## API Credentials

CloudTower use token as credentials of the API. It will passed as `Authorization` header in request

You SHOULD ask user to give you username, password and login source or a token directly, you MUST tell user MUST NOT directly pass username and password to you, instead to tell you which environment variables or configuration files has already storage them and ready to use.

## Authentication Workflow

### token workflow

If user directly pass token to you, you can directly use it to call API.

### username and password workflow

Call the `POST /login` operation to obtain a token, then use it as credentials for subsequent API calls. See the references for detailed information on the login operation and related schemas.

**References:**

- Resource: [User](resources/User.md)
- Operation: [Login](operations/Login.md)
- Request schema: [LoginInput](schemas/Login/LoginInput.md)
- Response schema: [WithTask_LoginResponse_](schemas/With/WithTask-LoginResponse.md)
- Data schema: [LoginResponse](schemas/Login/LoginResponse.md)

**Default login source:**

- `source` in `LoginInput` uses enum [UserSource](schemas/User/UserSource.md): `AUTHN`, `LDAP`, `LOCAL`, `SSO`.
- Use `LOCAL` as the default `source` value unless the user explicitly requests another source.

**Request and response schemas:**

See the referenced schema files for full request/response details.
