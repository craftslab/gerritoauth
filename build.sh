#!/bin/bash

docker build -t gerrit-plugins-oauth:3.4 .
docker run --name gerrit-plugins-oauth gerrit-plugins-oauth:3.4
docker cp gerrit-plugins-oauth:/workspace/output/oauth.jar .
docker rm gerrit-plugins-oauth
