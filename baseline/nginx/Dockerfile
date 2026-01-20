# Standard Nginx image (updated to more recent version)
FROM nginx:1.27-alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
