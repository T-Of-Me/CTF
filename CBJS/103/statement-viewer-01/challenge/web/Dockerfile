FROM openjdk:8u121-jdk-alpine

RUN apk add --no-cache bash unzip ca-certificates openssl wget

RUN addgroup -S tomcat && \
    adduser -S -G tomcat tomcat -h /usr/local/tomcat -s bash

ENV TOMCAT_VERSION=8.5.35
ENV CATALINA_HOME=/usr/local/tomcat
ENV PATH=$CATALINA_HOME/bin:$PATH
RUN mkdir -p ${CATALINA_HOME}
RUN wget -q -O /tmp/apache-tomcat.zip https://static.cyberjutsu-lab.tech/dependencies/apache-tomcat-8.5.35.zip && \
    unzip /tmp/apache-tomcat.zip -d /tmp && \
    mv /tmp/apache-tomcat-${TOMCAT_VERSION}/* ${CATALINA_HOME} && \
    rm -rf /tmp/apache-tomcat.zip /tmp/apache-tomcat-${TOMCAT_VERSION} && \
    chown -R tomcat:tomcat ${CATALINA_HOME}
RUN chmod +x ${CATALINA_HOME}/bin/*.sh

ENV MAVEN_VERSION=3.6.3
ENV MAVEN_HOME=/usr/share/maven
ENV PATH=$MAVEN_HOME/bin:$PATH
RUN wget -q -O /tmp/apache-maven-bin.tar.gz https://static.cyberjutsu-lab.tech/dependencies/apache-maven-3.6.3-bin.tar.gz && \
    tar -xzf /tmp/apache-maven-bin.tar.gz -C /tmp && \
    mv /tmp/apache-maven-3.6.3 /usr/share/maven && \
    rm -rf /tmp/apache-maven-bin.tar.gz

ARG ROOT_FLAG=CBJS{FAKE_FLAG_FAKE_FLAG}
RUN echo ${ROOT_FLAG} > /flag_$(head -c 8 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')

COPY ./conf/context.xml /usr/local/tomcat/webapps/manager/META-INF/
COPY ./conf/context.xml /usr/local/tomcat/webapps/host-manager/META-INF/
COPY ./conf/tomcat-users.xml /usr/local/tomcat/conf/

USER tomcat
ENV PATH=$PATH:/usr/local/tomcat

COPY --chown=tomcat:tomcat ./app/pom.xml /usr/local/tomcat/app/pom.xml
COPY --chown=tomcat:tomcat ./app/build.sh /usr/local/tomcat/app/build.sh

WORKDIR /usr/local/tomcat/app
RUN mvn dependency:go-offline -B

COPY --chown=tomcat:tomcat ./app/src /usr/local/tomcat/app/src
RUN mvn clean package -DskipTests
RUN rm -rf ${CATALINA_HOME}/webapps/ROOT; cp target/*.war ${CATALINA_HOME}/webapps/ROOT.war

ENV JPDA_ADDRESS=5005
ENV JPDA_TRANSPORT=dt_socket

ENTRYPOINT ["catalina.sh", "jpda", "run"]
