#!/bin/bash
set -ex

APP_NAME="finsight-statement-viewer"
TOMCAT_DIR="/usr/local/tomcat"
WEBAPPS_DIR="$TOMCAT_DIR/webapps"
WAR_PATH="target/${APP_NAME}.war"

mvn clean package -DskipTests || return 1

echo -e "${YELLOW}Deploying to Tomcat...${NC}"
rm -rf "$WEBAPPS_DIR/$APP_NAME" "$WEBAPPS_DIR/$APP_NAME.war" || true
rm -rf "$WEBAPPS_DIR/ROOT" || true
cp "$WAR_PATH" "$WEBAPPS_DIR/ROOT.war" || { echo -e "${RED}Deployment failed!${NC}"; exit 1; }
rm -rf target || return 1

[ "${1-}" == "skip-check" ] && exit 0

echo "Waiting for $APP_NAME to be deployed..."
until wget --quiet --spider "http://localhost:8080" > /dev/null; do
  printf '.'
  sleep 1
done

echo
echo "✅ Successfully built and deployed $APP_NAME"