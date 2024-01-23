# mini-tools
Cert-Validator
  1. Build with Maven.

        _mvn clean install_
  2. Run the executable jar file.

        _java -jar <path_to_jar_file>/cert-validator-1.0-SNAPSHOT-jar-with-dependencies.jar_

  3. Feed the console inputs and observe the logs for the trust chain validation.

  4. To enable the debug level logs, pass the property '-Dorg.slf4j.simpleLogger.defaultLogLevel=debug' as follows.

        _java -Dorg.slf4j.simpleLogger.defaultLogLevel=debug -jar <path_to_jar_file>/cert-validator-1.0-SNAPSHOT-jar-with-dependencies.jar_
