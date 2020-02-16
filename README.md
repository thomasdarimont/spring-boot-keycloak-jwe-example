PoC: Spring Boot Keycloak Signed & Encrypted JWT Example
----
This is a simple PoC for handling signed and encrypted JWTs with Spring Boot / Spring Security Oauth2 Resource Server.

Why this example? Keycloak supports signed and encrypted ID-Tokens for a while since this PR was merged (https://github.com/keycloak/keycloak/pull/5779),
however signed and encrypted access-tokens support is currently not available in Keycloak but an often requested feature. 

This PoC uses a [slightly patched version of Keycloak](https://github.com/thomasdarimont/keycloak/tree/issue/KEYCLOAK-XXX-Add-Support-for-AccessToken-Encryption) with support for signed and encrypted access-tokens in combination
with a small Spring Boot app that demonstrates how to handle signed and encrypted access-tokens.

This service generates a asymmetric RSA keypair to support encrypted access tokens.
The public part of the RSA-OAEP encryption Key is exposed via the `/oauth/jwks` endpoint of this service.
In our example Keycloak will fetch this public key to encrypt the access- and id-token sent to the consumer.

To decrypt the JWE access-token within the service, the private RSA key of this service is used. 
The decryption yields a nested signed JWT (JWS) which is the actual access-token with the claims, scope and role information for the user. 
The nested access-token needs to be verified by checking the signature with the Public-key which is associated with the asymmetric key pair
in the Keycloak realm whose private key was used to sign the nested access-token. The appropriate Key is identified by the "kid" header value
of the nested access-token JWS header and obtained via the configured: `spring.security.oauth2.resourceserver.jwt.jwk-set-uri`.
After signature validation, other common token claim validations are applied.   

# Keycloak

This following starts a local Keycloak instance accessible via: `http://localhost:8081/auth`

## Prepare Keycloak

### Checkout Keycloak PoC Branch. 
```
git clone https://github.com/thomasdarimont/keycloak/tree/issue/KEYCLOAK-XXX-Add-Support-for-AccessToken-Encryption
mvn clean package -DskipTests
```

### Run Keycloak from branch

Run a local keycloak server from master, e.g.:
```
Main-Class: org.keycloak.testsuite.KeycloakServer
Module: keycloak-testsuite-utils
JVM-Args:
-Dkeycloak.bind.address=0.0.0.0
-Djava.net.preferIPv4Stack=true
-Dkeycloak.connectionsJpa.url=jdbc:postgresql://localhost:5432/keycloak_4_x_master
-Dkeycloak.connectionsJpa.driver=org.postgresql.Driver
-Dkeycloak.connectionsJpa.driverDialect=org.hibernate.dialect.PostgreSQLDialect
-Dkeycloak.connectionsJpa.user=keycloak
-Dkeycloak.connectionsJpa.password=keycloak
-Dkeycloak.connectionsJpa.showSql=true
-Dkeycloak.connectionsJpa.formatSql=true
-Dprofile=COMMUNITY
-Dproduct.default-profile=COMMUNITY
-Dkeycloak.password.blacklists.path=/home/tom/dev/tmp/blacklists/
-Dcom.sun.net.ssl.checkRevocation=false
-Dkeycloak.truststore.disabled=true
-Dkeycloak.profile=COMMUNITY
-Dkeycloak.product.name=keycloak
-Dproduct.name=keycloak
-Dproduct.version=8.0.x
-Dkeycloak.profile.feature.account2=enabled
-Dkeycloak.profile.feature.scripts=enabled
-Dkeycloak.theme.welcomeTheme=keycloak
-XX:StartFlightRecording
```

### Import jwedemo Realm

Import the example realm with the admin-console via "Add-Realm", then use the following settings: 
Import: Select jwedemo-realm.export.json.
Name: jwedemo
Enabled: on

Click "Create".

Add a user with username "tester" and password "test". Assign the role "user" for the "jweclient".

#### Configure Client JWKS URL and Credentials
The client credentials of the jweclient in the jwedemo realm are already configured.
In the client credentials tab, select "Signed JWE" as client authenticator and check if the "Use JWKS URL" is "on" and
that the JWKS URL is `http://localhost:8080/oauth/jwks`, this is the endpoint where Keycloak obtains the 
RSA public key from the Spring Boot Service to encrypt the token.
Switch "client authenticator" back to "Client id and secret". This ensures Keycloak requires clientId / secret to obtain tokens
but also knows where to get client specific keys from... yes I agree, the admin-console UI could be much clearer here...

# Spring Boot Service

The following starts a Spring Boot Service available on http://localhost:8080 which exposes
two endpoints:
- /oauth/jwks - exposes the public RSA key used for token encryption by Keycloak
- /api/claims - exposes a protected endpoint that can be accessed with a signed and encrypted access-token and returns the contained claims 

## Prepare Spring Boot Service

### Generate Keystore
Execute the following in the current project root:
```
keytool -genkey \
        -alias jweclient-enc-v1 \
        -keystore src/main/resources/keystore.jks \
        -storepass geheim \
        -dname "CN=Thomas Darimont, OU=R&D, O=tdlabs, L=Saarbrücken, ST=SL, C=DE"  \
        -keyalg RSA \
        -keysize 2048
```

### Running the Spring Boot App
Just run the App class with the main method.

# Demo

## Retrieve Tokens
For demo purposes we obtain tokens via Resource Owner Password Credentials (ROPC) Grant - "Direct Access Grants" in Keycloak speech.
```
KC_USERNAME=tester
KC_PASSWORD=test
KC_CLIENT_ID=jweclient
KC_CLIENT_SECRET=418d630c-44cb-4f11-9dcc-a0c72dfc9f85
KC_ISSUER=http://localhost:8081/auth/realms/jwedemo

KC_RESPONSE=$( \
curl \
  -d "client_id=$KC_CLIENT_ID" \
  -d "client_secret=$KC_CLIENT_SECRET" \
  -d "username=$KC_USERNAME" \
  -d "password=$KC_PASSWORD" \
  -d "grant_type=password" \
  -d "scope=profile openid" \
  "$KC_ISSUER/protocol/openid-connect/token" \
)
echo $KC_RESPONSE | jq -C .
```

## Use encrypted Access-Token to access the /api/claims Endpoint
```
curl -v \
     -H "Authorization: Bearer $KC_ACCESS_TOKEN" \
     http://localhost:8080/api/claims | jq -C .
```

### Example Access Token
The example access token is an JWE (JSON Web Encryption) Token which contains a signed JWS (JSON Web Signature) token as encrypted payload.
```
eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00iLCJjdHkiOiJKV1QiLCJraWQiOiJqd2VjbGllbnQtZW5jLXYxIn0.qFSNh2CWuIK2dCKdsS22VpI6L1jwp5GP1_KIn8c3yxatLc5RejhalBgsF7UhRXuFaFjn6oubfkyzxvVRwK00hTj_IXK7M2wMBNmlDUOzRFxuAQ0wvr3S117rFPvImCSmC4PhcoEfSXS46mpDxqymb1MVqRoG0oNSSb_OeJS_MsQRnU8HlzjuZcHrA5TJg7kwsL2jJT8aHq9PXjMJJgWIhkU73gT52G1rvnuhsA4FQ3EuUk2wEs470W870orVybhA292p5wpXW9_gD2sq3hyM2YZmD2EtBeefOjs2EvkxQwmGozjGWUmRhGlHNQ-O_LOit2ikIJL71ZJmgG-4RTFBcw.6TzCP4tNhnVa9rpL.XlyC-JuYEzs9g5mgtn6FFlq9k4GtUOOMWtZfq4NixL19zTq_RlbI2Nh2amKn4YhTlHrCz6fAwEU2IIOj5l1HrYTMloiImVJmXZeBuiP_g6WRou5Uh7MjzuraIWVCXNsV6F5Cx5jTxHG-BYPA3Glr5kJ8uQi8KPPSs92YZLPwMhIpuyJGxrOA-l_t4Es2wYz2gfEZC4l4bQGXrPmQ8K5Bil7W94XzvEd93JxQUxUMZLmbmVgv5CUqnAWaNdldu2d-h5h8LRCRl2jnUQKw76z7OlVJDwF1HZxIAQjfBau_aV6UHK4-FbLUWHTGDF1kOwjK28VWL9vnrHbxxPRGuC81rONKZTFk_tDmURUcDcpy8IR3vje61D5GVVxZSwKdEl2x6DXrAoLdV_LZu34JsjLEi5Tkl8BiCdrjRXEG2LIVN952G347Yex1VcKaU4on2UokWPRWy2__1HjKI36AT0JRBVrT7hjyGtc9THvovAf5_PeLpio5QKyJJbycyNI5-Y5IpvrHm36JezbL7FwmN3gIjYYf4dhhXI1Q2RHbeMaqp1aHWmXDsoSxyRZe8GUrH3acEGkC66EJdw9qRCVtcsRE7SqDVm-xqMMWW2yN0hIDbYlvHvHXDdODgsri9dCI0mPsOh8ngyBQZHpCVI8bfDJkJE_wi-f7vfmPegL8NZFfu2lPRACkLIR7tqxkn2T4Lt95YoidOmQfwr3DQR-fvLnh2S29BGmTygVuizGA595vFKL3UTPgKNP5K5zozZrDEX9P1wB9PIdLevIXyptmTpJYY9g9QNafkPevaB4ThVXVgE1IUEjyZy4kJRiAyo1KzyGvXSdx5z7qYXpqNbJ5-uQ24QB-hRb6x5K_3xJrw-VnJ8opzWeALYbJlRDpAhvSOOzMef5dWHu7myHAZaubLY3T-INn86ievciY_msMQZSUtCbdIgQsFWOyCia0LBceNLcmikeph7d8nkELpWlC5KgdBy163AnJoQCT85ytSInvTM4bhEigA_Xeenk-KhS9lmBrQdAZZF5D7pzjZYKrO2438X6YbKwWXStZiGf0WRF7Uqn3lGTcrf3tCuA-vVWrQ7tu2W7nDWI2cRySqw1UYR_JHQ6eBfu2QEa1DkyzbnwLy3dHcGI75KlBq7uc3YnCTkI3_Fz3e74tUdjETSGHfS5szjvdCBBb-9k3Nos97E6nahWvy7z1WOhASmuvDR0iUrV7WJeIQUlisi-3-1kZT6UkUFMJrzaOv72MJhaCerVJc4hkQfcUqRPUsso3Z67cij67BQs0Iu-mIoQwChLkl4Hoy3KYC8jFeJf6M37N5zbvGXXK_DFwb70g9ZAoom1J9-6BinszjZ5cYv18MbNC8hVqvBKl29yGSI5RS7Qma_NJlX-m4MmEUAua4MTWYk1Rpaj8N3IVHBYKWnUQHkJFKUfOaQXlP3QywRc56g364v0PYHe0DF9Qab8WAvYlyQtWPXFrHRZJtvRBqSUBvlLilL96C2O5c7x2o9oXfziM2isvmxqhhE2KbaxJt43mTfD8Povb2YLz.3flZQa7bMj9RYQzveQCFaQ
```

#### JWE Header
The outer JWE uses asymmetric encryption and contains a signed JWT (JWS) as encrypted payload, denoted by the `cty: JWT` header entry.
    

This is the JOSE-header of the enclosing JWE. The `kid` refers to the keypair of the Spring Boot Service that was used to encrypt the JWE token.
```
{
  "alg": "RSA-OAEP",
  "enc": "A128GCM",
  "cty": "JWT",
  "kid": "jweclient-enc-v1"
}
```

#### Nested JWS

The nested signed JWT (JWS) is signed by Keycloak with private key of the active realm key.

The the nested JWS:
```
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQRDBwRWd4LUVRT09IYi1iVXZyb3F4dlVhaE5XbFc3dGg2OFEzRVRIT2RrIn0.eyJqdGkiOiJjOTVjZmRkYS1lNTgwLTRmMDYtOGQyOC01NGY3OWFjNDgxOTIiLCJleHAiOjE1ODE3ODU5ODgsIm5iZiI6MCwiaWF0IjoxNTgxNzg1Njg4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODEvYXV0aC9yZWFsbXMvandlZGVtbyIsInN1YiI6IjZjMjZhZmYwLTdiZjgtNDMwNi04NDEzLTBiYzZkZGI0MzZmMCIsInR5cCI6IkJlYXJlciIsImF6cCI6Imp3ZWNsaWVudCIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6IjMwZDhhZjlmLTk5ZWUtNDRlNC1hZDQ2LWI2YjhlOGQ2OGQ0MSIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsiandlY2xpZW50Ijp7InJvbGVzIjpbInVzZXIiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVGhlbyBUZXN0ZXIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0ZXIiLCJnaXZlbl9uYW1lIjoiVGhlbyIsImZhbWlseV9uYW1lIjoiVGVzdGVyIiwiZW1haWwiOiJ0b20rdGVzdGVyQGxvY2FsaG9zdCJ9.Fjdb8vS1PX-t2eyFVPpi_kCbu3jo77Bjs1LrMN_V3ggG7NPOJDTfFYuwgaA8OnUwR5tiSGkLR9_fy00jOhK5tDaV-BpD1MxjebtyJB0eLweg3UDnIUckKJZAiDa_4TKGxU1AuadDvv6ZpTEcAbwXy08jKjXIZw-5fwiZNCQL4YTe37J-xVBE_w37gejihc50QvLHn9fiJTP9V9Ynh9mdJ4y-iTlkucQ4idON3IoVKJzC2lBapUU7C4gi_j2TC-dtobbSWHYnfV6w1adOQhbqwHrCAF6EdK9F9zmsYRgXYJnIZ53xmCT4XW-a_TMTlTQAN_DvJ4vDUYoZzGc5XPEgqA
```

#### Nested JWS header decoded

This is the JOSE-Header of the nested JWS.   
The `kid` references the id of the Keycloak realm key pair with the public key to verify the signature of the JWS token. 
```
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "PD0pEgx-EQOOHb-bUvroqxvUahNWlW7th68Q3ETHOdk"
}
```

#### Nested JWS ClaimSet decoded
The the nested JWS ClaimSet:
```
{
  "jti": "c95cfdda-e580-4f06-8d28-54f79ac48192",
  "exp": 1581785988,
  "nbf": 0,
  "iat": 1581785688,
  "iss": "http://localhost:8081/auth/realms/jwedemo",
  "sub": "6c26aff0-7bf8-4306-8413-0bc6ddb436f0",
  "typ": "Bearer",
  "azp": "jweclient",
  "auth_time": 0,
  "session_state": "30d8af9f-99ee-44e4-ad46-b6b8e8d68d41",
  "acr": "1",
  "resource_access": {
    "jweclient": {
      "roles": [
        "user"
      ]
    }
  },
  "scope": "openid profile email",
  "email_verified": false,
  "name": "Theo Tester",
  "preferred_username": "tester",
  "given_name": "Theo",
  "family_name": "Tester",
  "email": "tom+tester@localhost"
}
```

### Example Response
```
{
  "sub": "6c26aff0-7bf8-4306-8413-0bc6ddb436f0",
  "resource_access": {
    "jweclient": {
      "roles": [
        "user"
      ]
    }
  },
  "email_verified": false,
  "iss": "http://localhost:8081/auth/realms/jwedemo",
  "typ": "Bearer",
  "preferred_username": "tester",
  "given_name": "Theo",
  "acr": "1",
  "nbf": "1970-01-01T00:00:00Z",
  "azp": "jweclient",
  "auth_time": 0,
  "scope": "openid profile email",
  "name": "Theo Tester",
  "exp": "2020-02-15T16:50:39Z",
  "session_state": "d23aab28-3344-45bb-827f-24f76ba587f3",
  "iat": "2020-02-15T16:45:39Z",
  "family_name": "Tester",
  "jti": "a33f5623-533e-487f-9c3c-31d8a20d958c",
  "email": "tom+tester@localhost"
}
```