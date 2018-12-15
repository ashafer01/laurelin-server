laurelin-server
===============

This is in very early stages of development as you can see.

This will be a simple, lightweight LDAP-speaking frontend server which will support a variety of data backends.

Currently the following are planned:

* Ephemeral/in-memory (no backend)
* In-memory with persistence in JSON, LDIF, etc., supporting local filesystem storage at minimum, and eventually cloud
  storage such as S3. With JSON, MongoDB and perhaps other NoSQLs will probably come cheap, too.
* SQL, utilizing a good ORM/abstraction layer to allow for maximum DBMS compatibility.
* Zookeeper - conceptually almost identical to LDAP already.

Overarching goals will be maximum backend compatibility in all senses of the phrase, and thus making it as easy as
possible to add support for more backends.



