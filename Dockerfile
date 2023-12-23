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

# Environement variables
ENV NODE_ENV=production

ENV DATABASE_URL=mongodb+srv://ndukachukwuemeka57:1cJrVihxSYBsFakm@cluster0.edj6psv.mongodb.net/user

ENV JWT_SECRET="7e3e3f94-8573-4ea3-9ae6-ba6738b0cfbc"

ENV GOOGLE_CLIENT_ID=392245325316-430g5brhcangsu07q78a9i0lnvjuhau3.apps.googleusercontent.com
ENV GOOGLE_CLIENT_SECRET=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

ENV SMTP_EMAIL=mail@glambox.ng
ENV SMTP_EMAIL_PASSWORD=Liverpool.2019
ENV SMTP_HOST=http://smtp.titan.email
ENV SMTP_PORT=465

# Assign `yarn start:prod` as the default command to run when booting the container
CMD ["yarn", "start:prod"]

EXPOSE 8079