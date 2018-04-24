#!/bin/bash
for item in $(cat repo_list)
do
    cd $item
    git pull origin master
    context=$(grep current config.yaml|cut -f2 -d " ")
    saasherder --context $context pull
    cd ../
done

IMAGE=$1
NAME_SPACE=$(echo $IMAGE|cut -f2 -d "/")
APP_NAME=$(echo $IMAGE|cut -f3 -d "/"|cut -f1 -d ":")
TAG=$(echo $IMAGE|cut -f3 -d "/"|cut -f2 -d ":")
REPO_DIR=$(grep $NAME_SPACE * -R|grep image|head -1|cut -f1 -d "/")
cd $REPO_DIR
CURRENT_CONTEXT=$(grep current config.yaml|cut -f2 -d " ")
GIT_URL=$(saasherder --context $CURRENT_CONTEXT get url $APP_NAME)
GIT_HASH=$(saasherder --context $CURRENT_CONTEXT get hash $APP_NAME)
TAG_LENGTH=$(saasherder --context $CURRENT_CONTEXT get hash_length $APP_NAME)
IMAGE_TAG=$(echo $GIT_HASH|cut -c1-$TAG_LENGTH)

echo "git-url=$GIT_URL"
echo "git-sha=$GIT_HASH"
echo "image-tag=$IMAGE_TAG"
