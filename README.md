# InstallCert

A fairly simple program to make a TLS connection, display the server 
certificates and allow you to install one of them locally.

## Background

This originally as Java program written by Andreas Sterbenz, and posted on a blog in Oct, 2006:
https://blogs.oracle.com/gc/entry/unable_to_find_valid_certification

Although that link is no longer valid, this program was useful to others and was found in another blog:
http://nodsw.com/blog/leeland/2006/12/06-no-more-unable-find-valid-certification-path-requested-target

From there, I found this GitHub repository:
https://github.com/escline/InstallCert

And forked it, to verify and understand its contents, and in so doing make some relatively minor 
changes and refactorings (mostly extracting classes and methods, and using Maven).

## Usage

Build this in Maven:
`mvn install`

Then, run the jar:
`java -jar target/installcert.jar <host[:port]>`

## And then?

What you do after that depends on your reason for grabbing this certificate. You might do some of the following items.

### Change the Alias
InstallCert will generate an alias for the certificate, but it might not be what you wanted. You can change the alias of the captured certificate:
```
keytool -changealias -alias <generated alias> -destalias <new alias> -keystore jssecacerts -storepass changeit -v 
```

### Export Certificate
You can extract the captured certificate from created jssecacerts keystore:
```
keytool -exportcert -alias <alias> -keystore jssecacerts -storepass changeit -file [host].cer
```

### Import Certificate
Import the exported certificate into system keystore (cacerts):
```
keytool -importcert -alias [host] -keystore [path to system keystore] -storepass changeit -file [host].cer
```

