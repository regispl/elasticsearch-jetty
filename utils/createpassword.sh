#!/bin/bash
java -cp elasticsearch-jetty-0.90.1-SNAPSHOT.jar:jetty-util-8.1.4.v20120524.jar:jasypt-1.9.1.jar com.sonian.elasticsearch.util.ExtendedPassword "$@"