#!/bin/bash

docker build --no-cache -t gerrit-plugins-oauth:3.4 .
docker run -it -d --name gerrit-plugins-oauth gerrit-plugins-oauth:3.4
docker cp gerrit-plugins-oauth:/workspace/output/oauth.jar .
docker rm -f gerrit-plugins-oauth
