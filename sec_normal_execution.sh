#!/bin/sh
javac -sourcepath src -classpath lib/*:lib/jersey-bundle_lib/*:src/Crypto/*.class:src/Exceptions/*.class:src/Client/*.class:src/Server/*.class:. src/Crypto/*.java src/Exceptions/*.java src/Server/*.java src/Client/*.java
konsole -e "bash -c \"java -cp ./lib/*:./lib/Jersey-bundle_lib/*:./src/:. Server.Server 8000 http://localhost:8000/ http://localhost:8500/ http://localhost:9000/ http://localhost:9500/; exec bash\""
konsole -e "bash -c \"java -cp ./lib/*:./lib/Jersey-bundle_lib/*:./src/:. Server.Server 8500 http://localhost:8000/ http://localhost:8500/ http://localhost:9000/ http://localhost:9500/; exec bash\""
konsole -e "bash -c \"java -cp ./lib/*:./lib/Jersey-bundle_lib/*:./src/:. Server.Server 9000 http://localhost:8000/ http://localhost:8500/ http://localhost:9000/ http://localhost:9500/; exec bash\""
konsole -e "bash -c \"java -cp ./lib/*:./lib/Jersey-bundle_lib/*:./src/:. Server.Server 9500 http://localhost:8000/ http://localhost:8500/ http://localhost:9000/ http://localhost:9500/; exec bash\""
konsole -e "bash -c \"java -cp ./lib/*:./lib/Jersey-bundle_lib/*:./src/:. Client.ClientApp http://localhost:8000/ http://localhost:8500/ http://localhost:9000/ http://localhost:9500/ < ./fileForTest.txt; exec bash\""

