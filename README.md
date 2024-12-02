<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="cmd/ui/public/img/logo-red-transparent-logo-only.svg">
        <img src="cmd/ui/public/img/logo-red-transparent-logo-only.svg" alt="BloodHound Community Edition" width='350' />
    </picture>
</p>

<div align="center">
<h1>BloodHoundAD</h1>
Six Degrees of Enterprise Domain Admin
<p></div>

<p align="center">
  <a href="#BloodHoundAD">About</a> •
  <a href="#How-to-Exec">Exec</a> •
  <a href="#Deploy-BloodHound">Deploy</a> •
  <a href="#Thanks-to">Main</a>
</p>

## BloodHound

BloodHound is a monolithic web application composed of an embedded React frontend with [Sigma.js](https://www.sigmajs.org/) and a [C#](https://csharp.net/) with [Go](https://go.dev/) based REST API backend. It is deployed with a [Postgresql](https://www.postgresql.org/) application database and a [Neo4j](https://neo4j.com/) graph database, and is fed by the [SharpHound](https://github.com/BloodHoundAD/SharpHound), or [SharpHoundAD](https://github.com/byt3n33dl3/SharpHoundAD), and [AzureHoundAD](https://github.com/byt3n33dl3/AzureHoundAD) data collectors.

## How does it `Exec` ?
It Uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment. Attackers can use BloodHound to quickly identify highly complex attack paths that would otherwise be impossible to find.

BloodHound is created and maintained by the BloodHound [Enterprise](https://bloodhoundenterprise.io) Team. The original BloodHound was created by [@wald0](https://www.twitter.com/_wald0), [@rvazarkar](https://twitter.com/CptJesus), [@byt3n33dl3](https://twitter.com/byt3n33dl3), and [@harmj0y](https://twitter.com/harmj0y).

## Running BloodHound Community Edition
Docker Compose is the easiest way to get up and running with BloodHound. Instructions below describe how to install and upgrade your deployment.

## Deploy BloodHound
Deploying BloodHound quickly with the following steps:

>- Install Docker [Desktop](https://www.docker.com/products/docker-desktop/).

Docker Desktop includes Docker Compose as part of the installation.

>- Download the Docker Compose YAML [file](examples/docker-compose/docker-compose.yml)

Save it to a directory where you'd like to run BloodHound. You can do this from a terminal application with 

```
curl -L https://ghst.ly/getbhce
```

>- On Windows: Execute the command

in CMD, or use `curl.exe` instead of `curl` in PowerShell.

>- Navigate to the folder

with the saved `docker-compose.yml` file and run `docker compose pull && docker compose up`.

>- Locate 

The randomly generated password in the terminal output of Docker Compose.

>- In a browser

Navigate to `http://localhost:8080/ui/login`. Login with a username of `admin` and the randomly generated password from the logs.

*NOTE: The default `docker-compose.yml` example binds only to localhost (127.0.0.1). If you want to access BloodHound outside of localhost, you'll need to follow the instructions in [README.md](examples/docker-compose/README.md) to configure the host binding for the container.*

## Upgrade BloodHound
Once installed, upgrade BloodHound to the latest version with the following steps:

>- Navigate to the folder

with the saved `docker compose.yml` file and run `docker compose pull && docker compose up`.

>- In a browser

navigate to `http://localhost:8080` and log in with your previously configured username and password.

## Importing sample data

The BloodHound team has provided some sample data for testing BloodHound without performing a SharpHound or AzureHound collection. That data may be found [here](https://github.com/byt3n33dl3/BloodHound/wiki/Example-Data).

## License from `@SpecterOps`

>- Apache License 2.0

## Licenses from `@GangstaCrew`

>- BSD-2-Clause License & AGPL 3.0

Unless otherwise annotated by a lower-level LICENSE file or license header, all files in this repository are released
under the `Apache-2.0` license. A full copy of the license may be found in the top level [LICENSE](LICENSE) file.

# Credits / `main`
- SpecterOps
    - [BloodHoundAD](https://github.com/BloodHoundAD/BloodHound)
    - GangstaCrew
- SpaceX

<p align="left">
<a href="https://github.com/byt3n33dl3"><img src="https://avatars.githubusercontent.com/u/151133481?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/chrismaddalena"><img src="https://avatars.githubusercontent.com/u/10526228?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/OceanExec"><img src="https://avatars.githubusercontent.com/u/171657497?s=200&v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/BloodHoundAD"><img src="https://bloodhound.readthedocs.io/en/latest/_images/bloodhound-logo.png" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/superlinkx"><img src="https://avatars.githubusercontent.com/u/466326?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/apps/dependabot"><img src="https://avatars.githubusercontent.com/in/29110?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/rvazarkar"><img src="https://avatars.githubusercontent.com/u/5720446?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mistahj67"><img src="https://avatars.githubusercontent.com/u/26472282?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/SpecterOps"><img src="https://avatars.githubusercontent.com/u/25406560?s=200&v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/benwaples"><img src="https://avatars.githubusercontent.com/u/66393111?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
</p>
