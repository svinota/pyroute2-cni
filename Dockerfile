FROM python:3.12-alpine

WORKDIR /app

RUN apk add git
RUN apk add vim
RUN apk add containerd-ctr
RUN pip install --no-cache-dir bottle
RUN pip install --no-cache-dir pydantic==2.10.6
RUN pip install --no-cache-dir zeroconf==0.146.1
RUN pip install --no-cache-dir pyroute2==0.9.1rc1

COPY . .
COPY start.sh /start.sh

CMD [ "/start.sh" ]
