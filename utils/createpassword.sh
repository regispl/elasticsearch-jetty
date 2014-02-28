#!/bin/bash
java -cp elasticsearch-jetty-1.0.0.jar:jetty-util-8.1.14.v20131031.jar:jasypt-1.9.1.jar com.sonian.elasticsearch.security.ExtendedPassword "$@"