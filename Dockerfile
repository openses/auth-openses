FROM node:8

# Create directory
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

# Install dependencies
COPY package.json /usr/src/app/
RUN npm install

# Copy source
COPY . /usr/src/app

#Copy custom oidc-provider login form
COPY login.js /usr/src/app/node_modules/oidc-provider/lib/views

RUN ["chmod", "+x", "/usr/src/app/my_wrapper_script.sh"]

EXPOSE 80
EXPOSE 443
EXPOSE 3010
EXPOSE 9000
EXPOSE 9001
EXPOSE 9002
CMD ./my_wrapper_script.sh