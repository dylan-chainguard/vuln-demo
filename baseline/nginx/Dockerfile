# Chainguard Nginx image (minimal, hardened base)
FROM cgr.dev/dylans-donuts.com/nginx:latest

# Copy custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
