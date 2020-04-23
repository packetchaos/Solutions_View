FROM ubuntu

RUN apt-get update
RUN apt-get install -y python3-pip
RUN pip3 install flask && pip3 install requests && pip3 install pyTenable

CMD mkdir /usr/src/app
CMD mkdir /usr/src/app/templates

ADD SC_newHost.py /usr/src/app/
ADD templates/index.html /usr/src/app/templates/
ENV PATH "$PATH:/usr/bin/env/"

EXPOSE 5001

WORKDIR /app

CMD python3 /usr/src/app/SC_newHost.py

