FROM python:3.7-stretch

RUN mkdir -p /app
WORKDIR /app

ADD requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED 1
CMD ./authproxy.py
