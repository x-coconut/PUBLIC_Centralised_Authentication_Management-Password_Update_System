# Copyright 2024 @x-coconut
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM python:3-alpine AS builder

ENV KEY_PATH=$KEY_PATH

# Install required libraries and tools
RUN apk add --no-cache \
    libxml2-dev \
    libxslt-dev \
    libffi-dev \
    gcc \
    musl-dev \
    python3-dev \
    autoconf \
    automake \
    g++ \
    make

RUN python -m pip install --upgrade pip

# pip install required libraries
COPY ./requirements.txt /tmp/requirements.txt
WORKDIR /tmp
RUN pip install -r requirements.txt && rm /tmp/requirements.txt

FROM python:3-alpine

COPY --from=builder /usr/local/lib/ /usr/local/lib

# add all python files to /app directory 
WORKDIR /app
COPY . .

# Set file permissions for all files in /app and /mnt
RUN chmod -R 777 /app
RUN mkdir -p /mnt && chmod 777 /mnt


# add the user worker, and switch to it
RUN adduser -S -H -s /usr/sbin/nologin worker
USER worker

# set the python wrapper as the entrypoint
ENTRYPOINT ["python3", "/app/python_wrapper.py" ]
