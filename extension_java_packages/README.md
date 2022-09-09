
# Java Packages extension

Java Packages Extensionn is an osquery extension meant to inspect jar files for java packages and classes. 
- Java packages can be inspected via path or directory. 
- Specific classes can be looked up within packages. 
- Uber jars are inspected recursively.
- `jar`, `war` and `ear` formats supported.

---

## Build

Follow these steps to build from the `extension_java_packages` folder

### Download libzip
`~/uptycs_osquery_extensions/extension_java_packages$ wget https://libzip.org/download/libzip-1.7.3.tar.xz`

### Extract libzip
`~/uptycs_osquery_extensions/extension_java_packages$ tar -xvf libzip-1.7.3.tar.xz`

### Replace CMakeLists.txt
`~/uptycs_osquery_extensions/extension_java_packages$ cp patch/LibZipCmake libzip-1.7.3/CMakeLists.txt`

### Create extension softlink in osqery build 
```
cd ~/osquery/
~/osquery$ ln -s ~/uptycs_osquery_extensions/extension_java_packages ./external/extension_java_packages
```

### Build Osquery
```
cd build
~/osquery/build$ cmake -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain ..
cmake --build . -j12
```

### Run extension
```
~/osquery/build/osquery$ sudo ./osqueryi --extension ~/osquery/build/external/extension_java_packages/java_packages_extension.ext --allow_unsafe
osquery> select * from osquery_extensions where name = 'java_packages';
+-------+---------------+---------+-------------+--------------------------------------+-----------+
| uuid  | name          | version | sdk_version | path                                 | type      |
+-------+---------------+---------+-------------+--------------------------------------+-----------+
| 51921 | java_packages | 0.0.1   | 0.0.0       | /home/batman/.osquery/shell.em.51921 | extension |
+-------+---------------+---------+-------------+--------------------------------------+-----------+
```

---

## Schema:
```
table_name("java_packages")
description("Lists all Java packages in a directory or specified jar/war/ear.")
schema([
    Column("artifact_id", TEXT, "Package artifact ID"),
    Column("group_id", TEXT, "Package group ID (i.e., com.xxx.xxx)"),
    Column("filename", TEXT, "Package filename"),
    Column("version", TEXT, "Package supplied version"),
    Column("description", TEXT, "Package supplied description/pretty name"),
    Column("size", BIGINT, "Size of file in bytes"),
    Column("path", TEXT, "Path to file within the JAR"),
    Column("directory", TEXT, "Path to the main (outer) JAR", index=True),
    Column("sha256", TEXT, "SHA256 hash of the file"),
    Column("file", TEXT, "Absolute path to the jar/war/ear file to get packages for"),
])
implementation("system/java_packages@genJavaPackages")
examples([
  "select * from java_packages where directory = '/home/user/my_project'", (Inspects all jars in folder)
  "select * from java_packages where file = '/home/user/my_project/my.jar'", (Inspects all packages within the jar)
  "select * from java_packages where file = '/home/user/my_project/my.jar' and filename = 'My.class'", (Inspects specific class within the jar)
])
```


### Example looking for vulnerable log4j packages:

#### Find processes running jar files:
```
~/osquery/build/osquery$ sudo ./osqueryi --extension ~/osquery/build/external/extension_java_packages/java_packages_extension.ext --allow_unsafe

osquery> select * from process_open_files where path like '%._ar';
  pid = 62491
   fd = 3
 path = /home/batman/vulnerable_java_package.war
```

#### Find vulnerable jars in an uber jar:

```
osquery> select * from java_packages where file = '/home/batman/vulnerable_java_package.war' and artifact_id like '%log4j%';
artifact_id = log4j-core
   group_id = org.apache.logging.log4j
   filename = log4j-core-2.17.0.jar
    version = 2.17.0
description = The Apache Log4j Implementation
       size = 4230003
       path = /home/batman/vulnerable_java_package.war/WEB-INF/lib/log4j-core-2.17.0.jar
  directory = /home/batman
     sha256 = 46875ad1407f84c83e0ea7d16dc88bd89df016f6ffb1fcad0176b9bcf86c4f6f
       file = /home/batman/vulnerable_java_package.war

artifact_id = log4j-api
   group_id = org.apache.logging.log4j
   filename = log4j-api-2.7.jar
    version = 2.7
description = The Apache Log4j API
       size = 219001
       path = /home/batman/vulnerable_java_package.war/WEB-INF/lib/log4j-api-2.7.jar
  directory = /home/batman
     sha256 = 2119221bfc18bc8b13f807a1eaa9bc12324efd0c6fb2a993a0a2445d4b47c263
       file = /home/batman/vulnerable_java_package.war

artifact_id = log4j-over-slf4j
   group_id = org.slf4j
   filename = log4j-over-slf4j-1.7.26.jar
    version = 1.7.26
description = Log4j implemented over SLF4J
       size = 23650
       path = /home/batman/vulnerable_java_package.war/WEB-INF/lib/log4j-over-slf4j-1.7.26.jar
  directory = /home/batman
     sha256 = 81a1c31befb21e3975064f43e0b1692b7fc2dc5f6d8dc3b6baaa7b8c3e5ddd5b
       file = /home/batman/vulnerable_java_package.war

artifact_id = log4j-vul-test
   group_id = com.uptycs
   filename = vulnerable_java_package.war
    version = 1.0-SNAPSHOT
description = 
       size = 26351307
       path = /home/batman/vulnerable_java_package.war
  directory = /home/batman
     sha256 = cd5e4868153baea8b59b65d57998f71c0e38d0931b1ccb0998ee0e785ebb82cd
       file = /home/batman/vulnerable_java_package.war

```

#### Find vulnerable classes in an uber jar based on class name and version:
```
osquery> select * from java_packages where file = '/home/batman/vulnerable_java_package.war' AND ( filename = 'JndiLookup.class' AND ((CAST(version as DOUBLE) < CAST('2.17' as DOUBLE) AND version NOT IN ('2.12.4', '2.3.2')) OR version = '2.17.0'));
artifact_id = org.apache.logging.log4j.core
   group_id = org.apache.logging.log4j
   filename = JndiLookup.class
    version = 2.17.0
description = The Apache Log4j Implementation
       size = 2937
       path = /home/batman/vulnerable_java_package.war/WEB-INF/lib/log4j-core-2.17.0.jar/org/apache/logging/log4j/core/lookup/JndiLookup.class
  directory = /home/batman
     sha256 = 
       file = /home/batman/vulnerable_java_package.war


```