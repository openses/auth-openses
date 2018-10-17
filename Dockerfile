FROM node:boron

# Create directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

# Install dependencies
COPY package.json /usr/src/app/
RUN npm install

# Copy source
COPY . /usr/src/app

EXPOSE 80
EXPOSE 443
CMD [ "npm", "start" ]