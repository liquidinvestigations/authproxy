FROM python:3.8-buster

RUN mkdir -p /app
WORKDIR /app

ADD requirements.txt ./
RUN pip install -r requirements.txt


## Add user ##
COPY . .

ENV PYTHONUNBUFFERED 1
CMD ./authproxy.py
