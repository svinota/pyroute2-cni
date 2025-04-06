FROM python:3.12-alpine

WORKDIR /app

# python modules
RUN apk add git
COPY requirements.txt .
COPY dist/* .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install *whl

# assets
COPY image/* .

# the engine
COPY pyroute2_plugin/pyroute2-cni-plugin .

CMD [ "/app/start.sh" ]
