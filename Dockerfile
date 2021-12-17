FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt -y update && apt -y upgrade && apt install -y --no-install-recommends \
    build-essential \
    gcc-multilib \
    git \
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
    # plotting ascii graphs for debug purposes
    libgraph-easy-perl \
    z3

# set up binaryninja
COPY BinaryNinja.zip /tmp/BinaryNinja.zip
RUN unzip /tmp/BinaryNinja.zip -d /opt/ && rm /tmp/BinaryNinja.zip && mkdir -p /root/.binaryninja/
# set up binaryninja license
COPY license.txt /root/.binaryninja/license.dat

# set up pydec
RUN mkdir -p /opt/decompiler && test -f /opt/decompiler/install_api.py || ln -s /opt/binaryninja/scripts/install_api.py /opt/decompiler/install_api.py

# update binja and cache this docker image
COPY Makefile.venv requirements.txt update_binja.py /opt/decompiler/
COPY ./dewolf-idioms/requirements.txt /opt/decompiler/requirements-compiler-idioms.txt
RUN make -f /opt/decompiler/Makefile.venv venv VENV_PATH=/opt/decompiler/.venv PREFIX=/opt/decompiler

COPY . /opt/decompiler
RUN mkdir -p /root/.binaryninja/plugins/ && cp -r /opt/decompiler/dewolf-idioms/ /root/.binaryninja/plugins/
WORKDIR /opt/decompiler
