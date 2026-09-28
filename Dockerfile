# Usage:
# Assuming you want to share the "files" subdirectory
# and your ngPost config is ngPost.docker.conf.
# $ docker build -t ngpost .
# $ docker run -it -v $PWD/files:/root/files -v $PWD/ngPost.docker.conf:/root/.ngPost ngpost ARGUMENTS

FROM debian:12

RUN apt-get update && apt-get install --no-install-recommends -y \
    git build-essential qt5-qmake qtchooser libqt5core5a \
    libqt5network5 libqt5gui5 libqt5widgets5 libqt5test5 \
    qtbase5-dev qtbase5-dev-tools \
    libargon2-dev libsodium-dev libssl-dev \
    par2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /usr/src/ngPost
WORKDIR /usr/src/ngPost/src

ENV QT_SELECT=qt5-x86_64-linux-gnu
RUN qmake ngPost.pro && make -j$(nproc)
RUN ln -s /usr/src/ngPost/src/ngPost /usr/local/bin/ngPost

WORKDIR /root
VOLUME /root/files

ENTRYPOINT [ "ngPost" ]
