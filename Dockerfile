# Start with a Node.js base image that uses Node v13
FROM node:20
WORKDIR /usr/src

# Copy the package.json file to the container and install fresh node_modules
COPY package*.json tsconfig*.json ./
RUN yarn

COPY ./prisma ./prisma
# generate prisma
RUN npx prisma generate

# Copy the rest of the application source code to the container
COPY ./src/ ./src/

# Transpile typescript and bundle the project
RUN yarn build

# Remove the original src directory (our new compiled source is in the `dist` folder)
RUN rm -r src

# Assign `yarn start:prod` as the default command to run when booting the container
CMD ["yarn", "start:prod"]

EXPOSE 8079