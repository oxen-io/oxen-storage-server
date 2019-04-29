FROM ubuntu:latest

RUN apt update && apt install -y build-essential git cmake libssl-dev libsodium-dev wget pkg-config
WORKDIR /usr/src/app

COPY install-deps-linux.sh install-deps-linux.sh
RUN ./install-deps-linux.sh
COPY . .
RUN mkdir -p build && cd build && sodium_LIBRARY_RELEASE="deps/sodium/lib" cmake .. -DBOOST_ROOT="/usr/src/app/deps/boost" -DOPENSSL_ROOT_DIR="/usr/include/openssl/" && cmake --build .

CMD ["build/httpserver/httpserver", "127.0.0.1", "3000"]
EXPOSE 3000
