We have 4 scripts: sec_byzantine_server.sh, sec_crash_server.sh,
sec_normal_2clients.sh, sec_normal_execution.sh

-sec_byzantine_server.sh runs 4 servers and 1 client where 1 of the servers is 
byzantine
-sec_crash_server.sh runs 4 servers where 1 of them crashes
-sec_normal_2clients.sh runs a normal execution of 4 servers and 2 concurrent 
clients
-sec_normal_execution.sh runs a normal execution 4 servers and 1 client  

To execute the testing scripts follow the following steps:
1-in every .sh file replace the word "konsole" with the respective terminal used
2-run each script with ./nameofthescript.sh
3-enjoy :)
