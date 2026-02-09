#!/bin/bash

docker build --no-cache -t gerrit-plugins-oauth:2.13 .
docker run -it -d --name gerrit-plugins-oauth gerrit-plugins-oauth:2.13
docker cp gerrit-plugins-oauth:/workspace/output/gerrit-oauth-provider.jar .
docker rm -f gerrit-plugins-oauth
