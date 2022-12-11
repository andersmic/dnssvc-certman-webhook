#!/bin/sh

if [ $# -eq 0 ]
then
  id=`date +%s`
else
  id=$1
fi

image=andersmic/cert-manager-webhook-dnsservices

docker buildx build --platform linux/amd64,linux/arm64 -t $image:$id -t $image:latest --push .

echo $id
