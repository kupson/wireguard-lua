FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		build-essential \
		ca-certificates \
		curl \
		iproute2 \
		liblua5.1-0-dev \
		lua-busted \
		lua5.1 \
		make \
		pkg-config \
		wireguard-tools \
		xz-utils \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /work
