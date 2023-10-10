# mini-tools
Cert-Validator
  1. Build with Maven.
        maven clean install
  2. Run the executable jar file.
        java -jar <path_to_jar_file>/cert-validator-1.0-SNAPSHOT-jar-with-dependencies.jar
  3. Feed the console inputs and observe the logs for the trust chain validation.
  4. To enable the debug level logs, pass the property '-Dorg.slf4j.simpleLogger.defaultLogLevel=debug' as follows.
        java -Dorg.slf4j.simpleLogger.defaultLogLevel=debug -jar <path_to_jar_file>/cert-validator-1.0-SNAPSHOT-jar-with-dependencies.jar
