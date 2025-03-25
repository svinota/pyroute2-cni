FROM python:3.12-alpine

WORKDIR /app

# tools
RUN apk add git
RUN apk add vim
RUN apk add containerd-ctr

# python modules
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# assets
COPY image/* .

# the engine
COPY pyroute2-cni-gateway/server.py .
COPY pyroute2-cni-plugin/pyroute2-cni-plugin .

CMD [ "/app/start.sh" ]
