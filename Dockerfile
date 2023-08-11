FROM python:3.11-bullseye

WORKDIR /fishy_remediator

RUN apt update && apt install -y
#RUN apt install openjdk-17-jre -y

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["python3", "remediator.py"]
