FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.22-1.1747241886

ENV LANGUAGE='en_US:en'

USER 0
RUN export NSS_CFG=$JAVA_HOME/conf/security/nss.fips.cfg && \
    sed -i 's/attributes.*/attributes(*,CKO_SECRET_KEY,*)={ CKA_SIGN=true CKA_ENCRYPT=true }/' $NSS_CFG

EXPOSE 8181
USER 185

ENV JAVA_APP_JAR="/deployments/app.jar"

COPY --chown=185 target/nimbus*.jar /deployments/app.jar
