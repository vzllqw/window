#!/bin/bash
docker build --tag sufei/admin .
docker rm -f sufei-test
docker run  --name=sufei-test -it --rm -v $(pwd)/app:/opt/admin sufei/admin python app.py && docker logs -f `docker ps -lq`
