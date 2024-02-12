# Schema-Check
Schema-Check is a cli tool which reports what parts of an IDM unit test are invalid relative to a directory schema. 

## How to use
This requires ldif schema files, an [eDirectory server](https://github.com/Jonathan-Zollinger/eDirectory-Compose) and an .env file.

### .env file
The env file provides what's needed to provide admin access to the eDir server. Never publish your .env file, nor save it somewhere you wouldn't save your bank information.
The env file will contain properties `IP`, `ADMIN_DN`, `ADMIN_SECRET`, `TRUST_STORE`, `TRUST_STORE_PASSWORD`, `SSL_PORT` for your eDir server. Extra properties cause no issue, which means you 
can re-use the .env file from your [eDirectory-Compose](https://github.com/Jonathan-Zollinger/eDirectory-Compose) if you have it.

This example is what I use for testing, which is copied from my eDir container's .env file. 
```shell
IP=172.17.2.139
NCP_PORT=2524
SERVER_CONTEXT=novell
SERVER_NAME=IDM-unit
TREENAME=trivir
ADMIN_DN=cn=admin,o=services
ADMIN_SECRET=trivir
LDAP_PORT=1389
SSL_PORT=1636
HTTP_PORT=1028
HTTPS_PORT=1030
TRUST_STORE=C:\Program Files\Zulu\zulu-18\lib\security\cacerts
TRUST_STORE_PASSWORD=changeit
```

#### How to add a cert to your keystore.
You'll need to add your eDirectory Server's cert to your keystore, or create a keystore if you dont have one. 

```shell
keytool -import -file .\edirCert.cer -keystore "C:\Program Files\Zulu\zulu-18\lib\security\cacerts"

```

## Install 

To install, simply place the binaries from this build on your
path. You can download (and unzip) the binaries from
[releases](releases) or [build](README.md#how-to-build-locally) them locally.

#### How to Build Locally

Building requires `maven 3.9.4` and `java 18`.  
1. Download this repo - you can later delete this if you want.
2. Navigate to the repo's base directory (The same directory where you find the `pom.xml` file)
3. call `mvn clean install -DskipTests` and watch the magic. 
<ul><ul><details><summary></summary>
<img src="docs/mvn-build.gif" alt="mvn clean install -DskipTests">
</details></ul></ul>

4. A new directory `target` will be produced where a number of other directories will be found. Among these is the `schema-check` directory.

#### Add schema-check to your PATH on Windows

> :round_pushpin: The schema-check.bat file is ultimately the executable which needs to be placed on your PATH. 
However, the .bat file requires other files to work, so be sure to include the whole directory `schema-check` and not just the .bat file.
><br><br>The `schema-check` folder content will look like this:
>```sh
>schema-check
>├───bin
>└───lib
>```

This example puts the `schema-check` directory in `C:\Program Files\` and requires admin priveleges. This also edits your powershell profile. Ensure you have a powershell profile before continuing.

```PowerShell
#Requires -RunAsAdministrator
if (-not (Test-Path -PathType Container .\schema-check\)) {
    Write-Warning "schema-check directory not in this dir. exiting..."
    return
}
if (Test-Path -PathType Container "C:\Program Files\schema-check\") {
    Write-Warning "schema-check already installed. Nothing to do. exiting..."
    return
}
mkdir "C:\Program Files\schema-check\"
cp schema-check
$env:Path = "$($env:Path);C:\Program Files\schema-check\bin"
echo '$env:Path = "$($env:Path);C:\Program Files\schema-check\bin"' >> $PROFILE
```



