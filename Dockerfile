FROM python:3.8-alpine

LABEL maintainer="Yahya Gholame <gholame.yahya@gmail.com>"
LABEL dockerfile-creator="Yahya Gholame <gholame.yahya@gmail.com>"

RUN addgroup -S lumen && \
    adduser -S lumen -G lumen

RUN apk add --no-cache gcc musl-dev libxml2-dev libxslt-dev nmap nmap-scripts openssl

USER lumen
WORKDIR /home/lumen
RUN pip install lumen-scanner

ENV PATH=/home/lumen/.local/bin:${PATH}

ENTRYPOINT ["lumen"]
CMD ["--help"]
