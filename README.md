# Schema-Check

## Install 

To install, simply place the binaries from this build on your
path. You can download (and unzip) the binaries from
[releases](releases) or [build](README.md#how-to-build-locally) them locally.

#### How to Build Locally

Building requires `maven 3.9.4` and `java 18`.  
1. Download this repo - you can later delete this if you want.
2. Navigate to the repo's base directory (The same directory where you find the `pom.xml` file)
3. call `mvn clean install` and watch the magic. 
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


