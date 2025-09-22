FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt -y update && apt -y upgrade && apt install -y --no-install-recommends \
    build-essential \
    cmake \
    gcc-multilib \
    git \
    python3-dev \
  # Binary Ninja deps https://docs.binary.ninja/guide/troubleshooting/index.html#headless-ubuntu
    libgl1-mesa-glx \
	libfontconfig1 \
    libxrender1 \
    libegl1-mesa \
    libxi6 \
    libnspr4 \
    libsm6 \
    libpython2.7 \
    libdbus-1-3 \
    libxkbcommon-x11-0 \
    # others
    virtualenv \
    unzip \
	astyle \
    graphviz \
    # plotting ascii graphs for debug purposes
    libgraph-easy-perl \
    z3

# set up binaryninja
COPY complete_repo.zip /tmp/complete_repo.zip
RUN unzip /tmp/complete_repo.zip -d /tmp/repo/ && rm /tmp/complete_repo.zip
RUN cp /tmp/repo/`ls /tmp/repo/ | grep dewolf-binja`/BinaryNinja.zip /tmp/BinaryNinja.zip
RUN unzip /tmp/BinaryNinja.zip -d /opt/ && rm /tmp/BinaryNinja.zip && mkdir -p /root/.binaryninja/
# set up binaryninja license
COPY license.txt /root/.binaryninja/license.dat

# set up pydec
RUN mkdir -p /opt/dewolf && test -f /opt/dewolf/install_api.py || ln -s /opt/binaryninja/scripts/install_api.py /opt/dewolf/install_api.py

# update binja and cache this docker image
COPY . /opt/dewolf
RUN cd /opt/dewolf & make -f /opt/dewolf/Makefile.venv venv VENV_PATH=/opt/dewolf/.venv PREFIX=/opt/dewolf

RUN mkdir -p /root/.binaryninja/plugins/
WORKDIR /opt/dewolf

# activate venv for docker exec
ENV VIRTUAL_ENV=/opt/dewolf/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
