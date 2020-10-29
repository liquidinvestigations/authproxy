FROM python:3.8-buster

ARG UNAME=liquid
ARG UID=666
ARG GID=666
RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME

# RUN mkdir -p /app && chown 666:666 /app
WORKDIR /app

ADD requirements.txt ./
RUN pip install -r requirements.txt


COPY . .

ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ./authproxy.py
