FROM python:3.12-alpine

WORKDIR /app

RUN apk add git
RUN apk add vim
RUN apk add containerd-ctr
RUN pip install --no-cache-dir -r ../requirements.txt

COPY . .
COPY ../pyroute2-cni-gateway .
COPY ../pyroute2-cni-plugin/pyroute2-cni-plugin .
COPY start.sh /start.sh

CMD [ "/start.sh" ]
