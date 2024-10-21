# Documentation for Centralised Authentication Management - Password Update System
This project is an extension for Keycloak which sends a user's username, password and allowed IP addresses to a RabbitMQ queue when a the user's password changes. This extension sends the password encrypted using an ECC (Elliptical Curve Cryptography) public key shared by a Python HTTP server. There is a python wrapper which retrieves the messages from RabbitMQ and runs the necessary code to update a user's password on Kali, RDG and Squid.

In this documentation, you will be required to follow any steps not contained within a dropdown. Anything else is either not necessary or may have multiple approaches.

If you want to run the system using Docker Compose, jump straight to [Running with Docker Compose](#running-with-docker-compose).

## Table of Contents
- [Development Environment](#development-environment)
- [Editing the Code](#editing-the-code)
  - [Required Changes](#required-changes)
  - [Updating Versions](#updating-versions)
- [Compiling the Code](#compiling-the-code)
- [Setup](#setup)
  - [Set Up Environment Variables](#set-up-environment-variables)
  - [Set Up Keycloak](#set-up-keycloak)
  - [Set Up AllowedIPs Attribute](#set-up-allowedips-attribute)
  - [Set Up RabbitMQ](#set-up-rabbitmq)
  - [Set Up `python/python_wrapper.py` with Docker](#set-up-pythonpython_wrapperpy-with-docker)
- [Adding the Extension to Keycloak](#adding-the-extension-to-keycloak)
- [Running the Code](#running-the-code)
- [Running with Docker Compose](#running-with-docker-compose)
    - [Networking Information](#networking-information)
    - [Editing the Code](#editing-the-code-1)
        - [Required Change](#required-change)
        - [Updating the IP Addresses Used](#updating-the-ip-addresses-used)
            - [If You Update Keycloak's IP Address](#if-you-update-keycloaks-ip-address)
            - [If You Update RabbitMQ's IP Address](#if-you-update-rabbitmqs-ip-address)
            - [If You Update Postgres' IP Address](#if-you-update-postgres-ip-address)
            - [If You Update `python_wrapper`'s IP Address](#if-you-update-python_wrappers-ip-address)
    - [HTTPS Certificate](#https-certificate)
    - [Running the System](#running-the-system)
    - [Code Explanation](#code-explanation)
        - [`libs`](#libs)
        - [`compose.yaml`](#composeyaml)
        - [`keycloak_dockerfile`](#keycloak_dockerfile)
        - [`keycloak_password_interceptor-1.0.jar`](#keycloak_password_interceptor-10jar)
        - [`python_server.py`](#python_serverpy)
        - [`python_wrapper.py`](#python_wrapperpy)
        - [`server_dockerfile`](#server_dockerfile)
        - [`wrapper_dockerfile`](#wrapper_dockerfile)
- [Code Explanation](#code-explanation-1)
    - [Encryption Information](#encryption-information)
    - [`keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProviderFactory.java`](#keycloak_password_interceptorsrcmainjavapasswordinterceptorproviderfactoryjava)
    - [`keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProvider.java`](#keycloak_password_interceptorsrcmainjavapasswordinterceptorproviderjava)
        - [*encrypt()*](#encrypt)
        - [*setup_queues_and_exchange()*](#setup_queues_and_exchange)
    - [`keycloak_password_interceptor/pom.xml`](#keycloak_password_interceptorpomxml)
    - [`keycloak_password_interceptor/src/main/resources/.../org.keycloak.credential.CredentialProverFactory`](#keycloak_password_interceptorsrcmainresourcesorgkeycloakcredentialcredentialproviderfactory)
    - [`python/python_server.py`](#pythonpython_serverpy)
    - [`python/python_wrapper.py`](#pythonpython_wrapperpy)
        - [RabbitMQ Queues](#rabbitmq-queues)
        - [*get_time()*](#get_time)
        - [*setup_queues_and_exchanges()*](#setup_queues_and_exchange-1)
        - [*process_message()*](#process_message)
        - [*decrypt_password()*](#decrypt_password)
        - [*update_machines()*](#update_machines)
        - [*save_key()*](#save_key)
        - [*delete_file()*](#delete_file)
        - [*callback_main_queue()*](#callback_main_queue)
        - [*callback_retry_queue()*](#callback_retry_queue)
        - [*main()*](#main)
    - [`python/Dockerfile`](#pythondockerfile)


<details>
<summary><h2>Development Environment</h2></summary>

During the development of this extension, the system which compiled the code had following:
- [Java](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html) 17.0.11
- [Apache Maven](https://maven.apache.org/download.cgi) 3.9.8
- Python 3.11.9

Maven managed the dependencies and plugins:
- Keycloak-services 25.0.2
- [APMQ-client](https://repo1.maven.org/maven2/com/rabbitmq/amqp-client/5.21.0/amqp-client-5.21.0.jar) 5.21.0
- [JSON](https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar) 20240303
- [Eciesjava](https://github.com/ecies/java)
- Maven-compiler-plugin 3.13.0
- Maven-shade-plugin 3.6.0

The Kali Linux virtual machine running the compiled code and Docker images had the following:
- Docker 20.10.25
- Docker Compose 2.29.2
- Python 3.11.9
- [Keycloak Docker image](https://quay.io/repository/keycloak/keycloak) 25.0.2
- [RabbitMQ Docker image](https://hub.docker.com/_/rabbitmq) 3.13.6

The `python_server.py` file uses the following modules:
- [Eciespy](https://pypi.org/project/eciespy/) 0.4.2
- [Cryptography](https://pypi.org/project/cryptography/) 39.0.1

If you choose not to run `python_wrapper.py` in a Docker container, the requirements.txt file lists the necessary modules.

To use the code with different versions, follow the instructions for [updating versions](#updating-versions)
</details>

## Editing the Code

<h3>Required Changes</h3> 

The following changes must be made in `keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProvider.java`:

- Update the IP address responsible for producing the public key for encryption:

    ```java
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        HttpGet request = new HttpGet("http://192.168.43.128:5000"); // UPDATE THIS IP
    ```

- Update the IP address, username, and password for the RabbitMQ server:

    ```java
    factory.setHost("192.168.43.128"); // UPDATE THIS TO IP FOR RABBITMQ SERVER
    factory.setPort(5672);
    factory.setUsername("guest"); // UPDATE TO RABBITMQ USERNAME
    factory.setPassword("guest"); // UPDATE TO RABBITMQ PASSWORD
    ```

The following change must be made in `python/python_wrapper.py`:

- Update the IP address, username and password for the RabbitMQ server:

    ```python
    def main():
        credentials = pika.PlainCredentials('guest', 'guest') # UPDATE USERNAME, PASSWORD
        connection_params = pika.ConnectionParameters(
            host='192.168.43.128', # UPDATE IP
            port=5672,
            credentials=credentials
        )
    ```
The following change must be made in `python/libs`:
- Replace the files inside the `python/libs` directory with the code to update users' details in Kali, RDG and Squid.

<details> 
<summary><h3>Updating Versions</h3></summary>

Versions for `keycloak_password_interceptor` can be updated in the *properties* section of the `keycloak_password_interceptor/pom.xml` file:

```xml
  <properties>

    <!-- UPDATE KEYCLOAK VERSION HERE -->
    <Keycloak.version>25.0.2</Keycloak.version>

    <!-- UPDATE APMQ-CLIENT VERSION HERE -->
    <RabbitMQ.version>5.21.0</RabbitMQ.version>

    <!-- UPDATE JSON VERSION HERE -->
    <JSON.version>20240303</JSON.version>

    <!-- UPDATE ECIESJAVA VERSION HERE -->
    <ECIES.version>master-SNAPSHOT</ECIES.version>

    <!-- UPDATE JAVA VERSION HERE -->
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>

    <!-- UPDATE COMPILER PLUGIN VERSION HERE -->
    <compilerPlugin.version>3.13.0</compilerPlugin.version>

    <!-- UPDATE SHADE PLUGIN VERSION HERE -->
    <shadePlugin.version>3.6.0</shadePlugin.version>

  </properties>
```
The latest versions for dependencies and plugins can be found [here](https://central.sonatype.com/).

Versions for `python/python_wrapper.py` running in a Docker container can be updated in `python/requirements.txt`.

</details>


## Compiling the Code

The code in `keycloak_password_interceptor` will require recompilation after any changes.

Install [Maven](https://maven.apache.org/download.cgi). Then, inside the `keycloak_password_interceptor` directory, run the following command to compile the code:

```sh
$ mvn clean package
```

`keycloak_password_interceptor/target/keycloak_password_interceptor-1.0.jar` is the location of the compiled code.


## Setup

### Set Up Environment Variables

Create an environment variable on the host machine called `KEY_PATH` and set it's value to `PATH/TO/Python/ECC_private_key.txt`.

This can be done by editing the `/etc/environment` file on the system and appending the following line to the end of the file:

```sh
KEY_PATH="/PATH/TO/python/ECC_private_key.txt"
```

Reboot the system for changes to take effect.

This environment variable is used by `python/python_server.py` and `python/python_wrapper.py` to access the file that stores the ECC private key for decryption.


<details>
<summary><h3>Set Up Keycloak</h3></summary>

Set up Keycloak with Docker using the following command:

```sh
$ docker run --name keycloak -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -v keycloak_data:/opt/keycloak/data quay.io/keycloak/keycloak:latest start-dev
```

This command:

- Names the container "keycloak"
- Sets both the username and password to "admin"
- Stores the container data in a volume named "keycloak_data"
- Uses the latest container image
- Uses development mode

Use the following commands to control the state of the container:

- ```sh
    $ docker stop keycloak
    ```
- ```sh
    $ docker start keycloak
    ```
- ```sh
    $ docker restart keycloak
    ```

[This link](https://www.keycloak.org/getting-started/getting-started-docker) contains instructions to set up a realm and users on Keycloak.
Note that any users created before [adding the extension to Keycloak](#adding-the-extension-to-keycloak) will not result in a message being sent to RabbitMQ.

</details>

<details>
<summary><h3>Set Up AllowedIPs Attribute</h3></summary>
This attribute holds a list of IP addresses a user is allowed to access. It is an attribute for Keycloak users which RabbitMQ receives. If you do not set this attribute up, the value sent to RabbitMQ for the AllowedIPs will be an empty list.
<br><br>

Visit the Keycloak [Administration Console](http://127.0.0.1:8080). Make sure you have selected the correct realm from the dropdown in the sidebar menu. In the *Configure* section of this sidebar menu, visit *Realm settings*. Then select the *User profile* tab and press the *create attribute* button. Fill in the following settings exactly as shown below: 

![Attribute name: "allowedIPs", Display name: "${allowedIPs}", Multivalued: On](/images/allowedIDs.PNG)

The value of this attribute can be edited from the *Users* section in the sidebar menu. When users log into their account, they do not see this attribute.

</details>

<details>
<summary><h3>Set Up RabbitMQ</h3></summary>

Set up RabbitMQ with Docker using the following command:

```sh
$ docker run --name rabbitmq -p 5672:5672 -p 15672:15672 -e RABBITMQ_DEFAULT_USER=guest -e RABBITMQ_DEFAULT_PASS=guest -v rabbitmq_data:/var/lib/rabbitmq rabbitmq:management
```
This command:

- Names the container "rabbitmq"
- Sets both the username and password to "guest"
- Stores the container data in a volume named "rabbitmq_data"
- Uses the latest container image with the management plugin enabled

Use the following commands to control the state of the container:

- ```sh
    $ docker stop rabbitmq
    ```

- ```sh
    $ docker start rabbitmq
    ```

- ```sh
    $ docker restart rabbitmq
    ```

To view the management console, visit [127.0.0.1:15672](http://127.0.0.1:15672) while the RabbitMQ Docker container is running.

The messages sent to RabbitMQ will be in the following form:
```json
{"allowedIPs":["192.168.1.1","127.0.0.1"],"username":"user3","encryptedPassword":"BC4WD0jqxG/Y3TZ4Ou4COi2FXg5xMVsVYXkoGxrzVx0sikABGsoGqVwzAb/mO4XyVDOzsT+vZRz4AWjhIKUhfy7JRSZC/YGB+2NnWy/Q0ya9tWx+13GUqbwjoBS0"}
```

</details>

<details>
<summary><h3>Set Up <code>python/python_wrapper.py</code> with Docker</h3></summary>

`python/python_wrapper.py` can be run directly on the main system or within a Docker container.

To set up the container, inside the `python` directory, run the following command:

```sh
$ docker build -t python_container .
```
This command creates a container called `python_container` using the files in the `python` directory.

To run the container, use the following command:

```sh
$ docker run -it --rm -e KEY_PATH=/mnt/ECC_private_key.txt -v "$(dirname "$KEY_PATH"):/mnt" python_container:latest
```
This command:
- displays the containers output in the terminal this command was run in
- deletes the container once it is stopped
- sets the `KEY_PATH` environment variable to `/mnt/ECC_private_key.txt
- mounts the directory of the ECC_private_key.txt file from the host machine to the container's /mnt directory
- runs the latest version of the container called `python_container`

Directory mounting is necessary as `python/python_server.py` does not run in this container so saves the ECC private keys needed for password decryption on the host machine. `python/python_wrapper.py` needs to access this file from inside the Docker container when decrypting the passwords. 

`python/python_wrapper.py` also creates and deletes files in this mounted directory. This means, in order for `python/python_wrapper.py` to work, the `python` folder on the host machine needs to have read and write permissions for all users.

</details>

## Adding the Extension to Keycloak 

Add the file `keycloak_password_interceptor/target/keycloak_password_interceptor-1.0.jar` into your Keycloak `/providers` directory.
If you set up Docker as explained in the instructions to [set up Keycloak](#Set-up-Keycloak), you can add the .jar file using the following command whilst the container is running:

```sh
$ docker cp PATH/TO/keycloak_password_interceptor-1.0.jar keycloak:/opt/keycloak/providers/
```

Next, restart the Docker container using:

```sh
$ docker restart keycloak
```

If you are not using a Docker container, you must run:

```sh
$ kc.sh build 
```

This is located in `/PATH/TO/KEYCLOAK/opt/keycloak/bin/kc.sh`

## Running the Code

To run the code successfully, make sure you are running:
- Keycloak (can be inside a Docker container)
- RabbitMQ (can be inside a Docker container)
- `python/python_server.py`
- `python/python_wrapper.py` (can be inside a Docker container)


<details>
<summary><h2>Running with Docker Compose</h2></summary>

To run this system with Docker Compose, disregard most of the rest of this documentation.

### Networking Information

| Network Name | IP Address | Container Name |
|------------|------------|------------|
| internal_1| 172.1.0.0/16 | |
| | 172.1.0.2 | Keycloak |
| | 172.1.0.3 | RabbitMQ |
| internal_2| 172.2.0.0/16 | |
| | 172.2.0.2 | Keycloak |
| | 172.2.0.3 | Postgres |
| internal_3| 172.3.0.0/16 | |
| | 172.3.0.2 | python_wrapper |
| | 172.3.0.3 | RabbitMQ |
| external_1| 172.11.0.0/16 | |
| | 172.3.0.2 | python_wrapper |
| host | | |
| | 127.0.0.1:5000 | python_server |

### Editing the Code

#### Required Change

The following change must be made in `keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProvider.java`:

Update the IP address responsible for producing the public key for encryption to the IP of the host machine (the machine running Docker Compose):

    ```java
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
        HttpGet request = new HttpGet("http://192.168.43.128:5000"); // UPDATE THIS IP
    ```

Recompile the code as specified in [Compiling the Code](#compiling-the-code).

Update `docker_compose/keycloak_password_interceptor-1.0.jar` to this newly compiled file.

<details>
<summary><h5>Updating the IP Addresses Used</h5></summary>

To update all the IP addresses specified in `docker_compose/compose.yaml`, change the IP addresses in this file. 

<details>
<summary><h6>If You Update Keycloak's IP Address:</h6></summary>

There are no updates needed to the code.

</details>

<details>
<summary><h6>If You Update RabbitMQ's IP Address:</h6></summary>

Follow [Required Changes](#required-changes) to update the IP address for RabbitMQ. Replace `docker_compose/python_wrapper.py` and `docker_compose/keycloak_password_interceptor-1.0.jar` with the updated files.

</details>

<details>
<summary><h6>If You Update Postgres' IP Address:</h6></summary>

Edit the following part of the `ENTRYPOINT` line in `docker_compose/keycloak_dockerfile` to contain the new IP for Postgres:

```Dockerfile
"--db-url=jdbc:postgresql://172.2.0.3:5432/keycloakDB"
```

</details>

<details>
<summary><h6>If You Update <code>python_wrapper</code>'s IP Address:</h6></summary>

There are no updates needed to the code.

</details>

</details>

### HTTPS Certificate

To connect Keycloak to a database, Keycloak needs to enforce HTTPS. To comply with this, `docker_compose/keycloak.jks` provides a self-signed certificate. Replace this file with a real certificate. Update the password used for this certificate in the following part of `docker_compose/compose.yaml`:

```yaml
KEYCLOAK_TLS_KEYSTORE_PASSWORD: password
```
Also update the password in the following part of `docker_compose/keycloak_dockerfile`:

```Dockerfile
ENV KEYCLOAK_TLS_KEYSTORE_PASSWORD=password
```

### Running the System

Inside the `docker_compose` directory, run the follwoing command:

```sh
$ docker-compose up
```

To stop the system running, run the following command:

```sh
$ docker-compose down --remove-orphans
```

Once the system is running the Keycloak admin console can be accessed at:
- [https://172.1.0.2:8443](https://172.1.0.2:8443)
- [https://172.2.0.2:8443](https://172.2.0.2:8443)

The RabbitMQ Management Console can be accessed at:
- [http://172.1.0.3:15672](http://172.1.0.3:15672)
- [http://172.3.0.3:15672](http://172.3.0.3:15672)

Set up the allowedIPs attribute as specified in [Set Up AllowedIPs Attribute](#set-up-allowedips-attribute)


<details>
<summary><h3>Code Explanation</h3></summary>

All of the below files are located inside the `docker_compose` directory.

<details>
<summary><h4><code>libs</h4></code></summary>

This is the same as `python/libs`.

</details>

<details>
<summary><h4><code>compose.yaml</h4></code></summary>

This file sets up the Docker containers for this system.

The `keycloak` container depends on the `postgres` container and `python_server` container. This meansthe `keycloak` container won't run until those containers have been started.

The `rabbitmq` container performs a health check so it can be identified when the container is ready to accept connections.

The `python_wrapper` container depends on the `rabbitmq` container being "healthy" and the `python_sever` container having started. This means the `python_wrapper` container won't run until these conditions are met.

</details>

<details>
<summary><h4><code>keycloak_dockerfile</h4></code></summary>

This file is used to set up the `keycloak` Docker container. It uses the latest Keycloak docker image. It then copies `docker_compose/keycloak_password_interceptor-1.0.jar` into the Keycloak `providers` directory on the container. It then copies `docker_compose/keycloak.jks` into the Keycloak `conf` directory on the container. The environment variables `KEYCLOAK_TLS_KEYSTORE` and `KEYCLOAK_TLS_KEYSTORE_PASSWORD` are set to reflect the HTTPS certificate location and password. The entrypoint is then set so that the container runs the following command when it starts:

```sh
$ ./opt/keycloak/bin/kc.sh start --https-key-store-file=/opt/keycloak/conf/keycloak.jks --db=postgres --db-url=jdbc:postgresql://172.2.0.3:5432/keycloakDB --db-username=user --db-password=password --db-schema=public --hostname-strict=false
```

</details>

<details>
<summary><h4><code>keycloak_password_interceptor-1.0.jar</h4></code></summary>

This is the same as `keycloak_password_interceptor/target/keycloak_password_interceptor-1.0.jar` except it has had the IP addresses used updated to reflect the networks used by Docker Compose.

</details>

<details>
<summary><h4><code>python_server.py</h4></code></summary>

This is the same as `python/python_server` except it uses an environment variable to get the location to save the ECC private key to so that the `python_wrapper` can access this file.

</details>

<details>
<summary><h4><code>python_wrapper.py</h4></code></summary>

This is the same as `python/python_wrapper` except it has had the IP addresses used updated to reflect the networks used by Docker Compose.

</details>

<details>
<summary><h4><code>server_dockerfile</h4></code></summary>

This file is used to set up the `python_server` Docker container. It installs the necessary libraries. `python_server.py` from the `docker_compose` directory is then copied to the `app` directory inside the container. The `mnt` directory is created inside the container and both `app` and `mnt` are given full permissions for any user. A user called `worker` is then created on the machine. The current user is switched from `root` to `worker`. `app/python_wrapper.py` is set to run (as the entrypoint) when the container is run.

</details>

<details>
<summary><h4><code>wrapper_dockerfile</h4></code></summary>

This is the same as `python/python_wrapper` except it explicitly defines which files to copy to the container since there is no `.dockerignore` file in the `docker_compose` directory. It also doesn't set up the `KEY_PATH` environment variable as this is handled by `docker_compose/compose.yaml`.

</details>





</details>

</details>

## Code Explanation

<details>
<summary><h3>Encryption Information</h3></summary>

`python/python_server.py` produces a public and private ECC key using the [eciespy](https://pypi.org/project/eciespy/) library using the secp256k1 curve (also known as NIST P-256 and prime256v1). For each HTTP request to [127.0.0.1:500](http://127.0.0.1:5000), the Python server generates a new set of keys.

The public key uses X.509 format. The Python server DER encodes the key and Base64 encodes it. The Python server shares this key as the contents of the HTTP response.

Example response from `python_server.py` 

```sh
$ curl http://127.0.0.1:5000
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj5jt4yX1khzqKtF9T5EnskYOIXUWmmwgl7SfqRdRBAMFuXEnYQiurxh/HPOn3TK2p5vhbc5nC8xuk6p0Xl9Znw==
```

The private key uses the PKCS#8 format. The Python server PEM encodes the key then saves it to `python/ECC_private_key.txt`

Example contents of `ECC_private_key.txt`

```txt
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgm8ksBRw2Srx3+O8V
WmmyVXzGrqt+YhRCA6u6yQ9GrRihRANCAARdNzD7rjsl62+zzc51o38Ls8xJztQ/
tHSlSnt6SswEi1sI4fcXvtN9a4wBQQbZKUSd10FC3PR2c88enUGsda3A
-----END PRIVATE KEY-----
```

`keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProvider.java` retrieves the Base64 encoded public key in DER format via HTTP request from the Python server and decodes it from Base64. The provider then makes use of the [eciesjava](https://github.com/ecies/java) library and encrypts the password using ECIES (Elliptic Curve Integrated Encryption Scheme). This is then and encoded using Base64.

`python/python_wrapper.py` retrieves the encrypted password from RabbitMQ and saves the ECC private key from `ECC_private_key.txt` to a seperate file to enusure its contents isn't overwritten. 

The *decrypt_password()* function in `python_wrapper.py` decodes the encrypted password from Base64. It then serialises the private key from PEM format so it can be used for decryption. It uses the [eciespy](https://pypi.org/project/eciespy/) libary to decrypt the password using the private key.

</details>

<details>
<summary><h3><code>keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProviderFactory.java</code></h3></summary>

`PasswordInterceptorProviderFactory` implements Keycloak's [`CredentialProviderFactory`](https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/credential/CredentialProviderFactory.java) and the *create()* method creates instances of `PasswordInterceptorProvider`. The *getID()* method returns the ID value assigned to this factory. All other methods are blank as the parent factory, `CredentialProviderFactory` provides the rest of the required functionality.

Keycloak's [`PasswordCredentialProviderFactory`](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/credential/PasswordCredentialProviderFactory.java) also implements `CredentialProviderFactory` and creates instances of Keycloak's [`PasswordCredentialProvider`](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/credential/PasswordCredentialProvider.java). 
The *PROVIDER_ID* variable in `PasswordInterceptorProviderFactory` therefore holds "keycloak-password" as Keycloak's `PasswordCredentialProviderFactory` uses "keycloak-password" as its ID value. Using a different ID activates both factories, causing each to create its respective instance of `PasswordInterceptorProvider` or `PasswordCredentialProvider`, which results in duplicated settings on users' account pages.
</details>

<details>
<summary><h3><code>keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProvider.java</code></h3></summary>

The `PasswordInterceptorProvider.java` file contains the logic to capture users' details, encrypt the password and send the details to RabbitMQ. This provider extends Keycloak's [`PasswordCredentialProvider`](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/credential/PasswordCredentialProvider.java). `PasswordInterceptorProvider` overwrites Keycloak's `CreateCredential` method and some of the code comes directly from the [`CreateCredential`](https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/credential/PasswordCredentialProvider.java) source code.

In `PasswordInterceptorProvider`, after the point in the code from `CreateCredential` that updates the user's password, the provider makes a HTTP request to the provided IP, attempting to get the public ECC key (which is in X.509 format, Base64 encoded and DER encoded). The provider then converts this key into a key object and uses it to encrypt the user's new password with ECIES, using [eciesjava](https://github.com/ecies/java).

The provider creates a JSON object (and then converts it to a string), containing the user's username, encrypted password and the [AllowedIPs attribute](#Set-up-AllowedIPs-Attribute).

`PasswordInterceptorProvider` then tries to establish a connection with RabbitMQ using the provided IP address, port, username and password. The provider declares the necessary queues and exchanges for RabbitMQ (only creating them if they don't already exist).

The provider then sends the JSON string as a message to the queue.

<details>
<summary><h4><em><code>encrypt()</code></em></h4></summary>

This function takes the Base64 encoded encrypted password and the public key Base64 encoded and DER encoded as parameters.

It Base64 decodes the public key, meaning it is now just DER encoded. It then changes the key from DER format to a string of hex as this is the format needed for the [eciesjava](https://github.com/ecies/java) encryption function. The [eciesjava](https://github.com/ecies/java) encryption function is used to encrypt the password, returning a stringof hex that represents the encrypted password. This is then Base64 encoded. The function returns this Base64 encoded string that represents the encrypted password.


</details>

<details>
<summary><h4><em><code>setup_queues_and_exchange()</code></em></h4></summary>

This function declares the RabbitMQ exchange and queues. It then binds the queues to the exchange.

</details>


</details>

<details>
<summary><h3><code>keycloak_password_interceptor/pom.xml</code></h3></summary>

The `pom.xml` file allows [Maven](https://maven.apache.org/download.cgi) to manage dependencies and plugins. 

`pom.xml` contains 3 dependencies:
- `keycloak-services` - to integrate with Keycloak
- `amqp-client` - to integrate with RabbitMQ
- `json` - to format the data as JSON

`pom.xml` contains 2 plugins:
- maven-compiler-plugin - to specify the java version to use in compilation
- maven-shade-plugin - to include the compiled code, including the `amqp-client` and `json` dependencies into a single file

The versions of these dependencies and plugins can be updated as explained in the instructions to [update versions](#updating-versions).

</details>

<details>
<summary><h3><code>keycloak_password_interceptor/src/main/resources/.../org.keycloak.credential.CredentialProviderFactory</code></h3></summary>

This file tells Keycloak that `keycloak_password_interceptor/PasswordInterceptorProviderFactory.java` is an implementation of the Keycloak's CredentialProviderFactory interface. In short, it is needed to make Keycloak recognise and load the extension.


</details>

<details>
<summary><h3><code>python/python_server.py</code></h3></summary>

For each request to [127.0.0.1:5000](http://127.0.0.1:5000), `python_server.py` generates an ECC public and private key. The Private key uses the PKCS#8 format and is PEM encoded. The Python server prints this key to the terminal. The public key uses X.509 format and is DER encoded then Base64 encoded. The Python server shares the public key as the content of the HTTP response.

</details>

<details>
<summary><h3><code>python/python_wrapper.py</code></h3></summary>

`python_wrapper.py` retrieves messages from RabbitMQ, attempts the decrypt the password and send it to the code in `/python/libs` to update the user's information on Kali, RDG and Squid. If this fails, exponential backoff is used when retrying to process the message. After 1 fail, the message is processed again after 5 minutes, if this fails, it is tried again after 25 minutes. The 6th and final attempt has a delay of 3125 minutes (2 days, 4 hours, 5 minutes). If the message still cannot be successfully processed, it is sent to a RabbitMQ queue where it can be manually retrieved and dealt with. When a message is processed successfully, it is removed from all RabbitMQ queues.

<details>
<summary><h4>RabbitMQ Queues</h4></summary>
The queues on used on RabbitMQ to implement exponential backoff work as follows:

- Messages are sent to `main_queue` by `keycloak_password_interceptor/src/main/java/.../PasswordInterceptorProvider.java`.
    - The message is processed.
    - The mesage is removed from the queue

- If an error occured while processing it, the message is sent to `waiting_5_min`.
    - After 5 minutes, the message expires on the `waiting_5_min` queue.
    - It is removed from the queue
    
- It is sent to the `retry` queue.
    - The message is processed.
    - The mesage is removed from the queue
    
- If an error occured while processing it, the message is sent to `waiting_25_min`.
    - After 25 minutes, the message expires on the `waiting_25_min` queue.
    - It is removed from the queue
    
- It is sent to the `retry` queue.
    - The message is processed.
    - The mesage is removed from the queue
    
- If an error occured while processing it, the message is sent to `waiting_125_min`.
    - After 125 minutes, the message expires on the `waiting_125_min` queue.
    - It is removed from the queue
    
- It is sent to the `retry` queue.
    - The message is processed.
    - The mesage is removed from the queue
    
- If an error occured while processing it, the message is sent to `waiting_625_min`
    - After 625 minutes, the message expires on the `waiting_625_min` queue.
    - It is removed from the queue
    
- It is sent to the `retry` queue.
    - The message is processed.
    - The mesage is removed from the queue
    
- If an error occured while processing it, the message is sent to `waiting_3125_min`
    - After 3125 minutes, the message expires on the `waiting_3125_min` queue.
    - It is removed from the queue
    
- It is sent to the `retry` queue.
    - The message is processed.
    - The mesage is removed from the queue
    
- If an error occured while processing it, the message is sent to `failed_messages`.


The following diagram also shows the route a message will take through the queues if it fails to be processed each time:
![Diagram showing the route a message will take through the queues](/images/queues.png)

</details>



<details>
<summary><h4><em><code>get_time()</code></em></h4></summary>

This function returns the current date and time.

</details>

<details>
<summary><h4><em><code>setup_queues_and_exchange()</code></em></h4></summary>

This function takes the RabbitMQ connection channel as a parameter and uses this to declare the RabbitMQ exchange and queues. It then binds the queues to the exchange.

</details>

<details>
<summary><h4><em><code>process_message()</code></em></h4></summary>

This function takes the body of the message and the number associate with its decryption key as parameters. It extracts the username, encrypted password and allowedIPs values from the JSON in the message body. It then calls the *decrypt_password()*, *update_machines()* and *delete_file()* functions. This function returns an error code to represent if it executed successfully. An error code of 0 means there were no errors and an error code of 1 means there was an error.

</details>

<details>
<summary><h4><em><code>decrypt_password()</code></em></h4></summary>

This function takes the encrypted password and the number associated with its decryption key as parameters. It checks the file containing the decryption key exists and then retrieves the PEM encoded ECC decryption key from it. It then serialises the private key using it with the [eciespy](https://pypi.org/project/eciespy/) library to decrypt the encrypted password. The function then returns the plaintext password and an error code. An error code of 0 means there were no errors and an error code of 1 means there was an error.

</details>

<details>
<summary><h4><em><code>update_machines()</code></em></h4></summary>

For each IP address in the allowedIPs attribute, this function calls the necessary methods in `python/libs` to update the user's details in Kali, RDG and Squid. This function returns an error code to represent if it executed successfully. An error code of 0 means there were no errors and an error code of 1 means there was an error.

</details>


<details>
<summary><h4><em><code>save_key()</code></em></h4></summary>

This function takes the private key stored in `python/ECC_private_key.txt` and saves it to a new file. This is necessary to stop the private key in `ECC_private_key` being overwritten in case multiple messages arrive in the `main_queue` in a short amount of time. 

The function generates a random 3 digit code and checks if a decryption key file already uses this code in its name. If the code is alrady used, another code is generated, until a unique code is found. The private key is then saved in a file which uses this code in its name. This function then returns this 3 digit code associated with the decryption key for that message and an error code. An error code of 0 means there were no errors and an error code of 1 means there was an error.

</details>

<details>
<summary><h4><em><code>delete_file()</code></em></h4></summary>

This function takes the number associated with the decryption file to be deleted as a parameter. It then checks if this file exists and then deletes the file.

</details>

<details>
<summary><h4><em><code>callback_main_queue()</code></em></h4></summary>

This function runs when a message arrives in the `main_queue`. It extracts the message and then runs the *save_key()* and *process_message()* functions. It then removes the message from the `main_queue`. If an error occured at any point when processing the message, the message is sent to the `waiting_5_min` queue, with the header containing the number linked to this messages decryption key (returned by the *save_key()* function).

</details>

<details>
<summary><h4><em><code>callback_retry_queue()</code></em></h4></summary>

This function runs when a message arrives in the `retry` queue. It extracts the message and its headers and then runs the *process_message()* function. The message is then removed from the `retry` queue. If an error occured at any point when processing the message, the function determines which queue to send the message to next based on how many times it has been retried. The number of times a message has been retried is stored in the header of each message. The message is then sent to the appropriate queue with the retry-count header updated.

</details>


<details>
<summary><h4><em><code>main()</code></em></h4></summary>

This function initialises the connection to the RabbitMQ server and calls the *setup_queues_and_exchange()* function. It then links the `main_queue` and `retry` queue to their respective callback functions.


</details>

</details>


<details>
<summary><h3><code>python/Dockerfile</code></h3></summary>

This file is used to set up `python/python_wrapper.py` in a Docker container. It sets the `KEY_PATH` enviroment variable in the container to the same value held in the `KEY_PATH` environment variable on the host machine. It then installs the necessary libraries, including those in `python/requirements.txt`. The files from the `python` directory are then copied to the `app` directory inside the container, excluding files listed in `python/.dockerignore`. The `mnt` directory is created inside the container and both `app` and `mnt` are given full permissions for any user. A user called `worker` is then created on the machine. The current user is switched from root to `worker`. `app/python_wrapper.py` is set to run (as the entrypoint) when the container is run.

</details>
