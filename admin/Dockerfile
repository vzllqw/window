FROM python:3-alpine
MAINTAINER Fei Su <fei.su@cm-dt.com> 
WORKDIR /opt/admin
RUN apk add --update tzdata \
bash \
build-base gcc g++ automake autoconf zlib-dev python3-dev make linux-headers
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime 
COPY app/requirements.txt /opt/
RUN pip install -r /opt/requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]
EXPOSE 8888

