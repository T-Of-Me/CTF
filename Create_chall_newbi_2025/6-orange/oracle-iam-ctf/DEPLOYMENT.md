# Deployment Guide

## Quick Start

### Using Docker Compose (Recommended)

```bash
docker-compose up -d
```

Access the challenge at: `http://localhost:14000`

### Building from Source

```bash
docker build -t oracle-iam-ctf .
docker run -d -p 14000:14000 --name oracle-iam oracle-iam-ctf
```

## Verification

### Check Service Status

```bash
docker-compose ps
```

Expected output:
```
NAME                      STATUS              PORTS
oracle-iam-vulnerable     Up 2 minutes        0.0.0.0:14000->14000/tcp
```

### Test Connectivity

```bash
curl http://localhost:14000/identity/rest/v1/info
```

Expected response:
```json
{
  "product": "Oracle Identity Manager",
  "version": "12.2.1.4.0",
  "component": "REST WebServices",
  "status": "running"
}
```

### Run Automated Tests

```bash
chmod +x test.sh
./test.sh
```

## Configuration

### Environment Variables

Edit `docker-compose.yml` to customize:

```yaml
environment:
  - FLAG=FLAG{your_custom_flag_here}
```

### Port Configuration

Change port mapping in `docker-compose.yml`:

```yaml
ports:
  - "8080:14000"  # Host:Container
```

Access via: `http://localhost:8080`

### Custom Credentials

Edit `app.py` to change default admin credentials:

```python
ADMIN_CREDENTIALS = {
    'username': 'admin',
    'password': 'YourSecurePassword123!'
}
```

## Troubleshooting

### Port Already in Use

Error: `Bind for 0.0.0.0:14000 failed: port is already allocated`

Solution:
```bash
# Find process using port 14000
sudo lsof -i :14000

# Kill the process or change port in docker-compose.yml
ports:
  - "14001:14000"
```

### Container Won't Start

Check logs:
```bash
docker-compose logs -f
```

Common issues:
1. **Missing dependencies**: Rebuild image
   ```bash
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Permission errors**: Check file permissions
   ```bash
   chmod -R 755 .
   ```

### Connection Refused

1. Check if container is running:
   ```bash
   docker ps | grep oracle-iam
   ```

2. Check container logs:
   ```bash
   docker logs oracle-iam-vulnerable
   ```

3. Verify port mapping:
   ```bash
   docker port oracle-iam-vulnerable
   ```

### Exploit Not Working

1. **Verify target URL**:
   ```bash
   curl http://localhost:14000/identity/rest/v1/info
   ```

2. **Check exploit script**:
   ```bash
   python3 exploit.py http://localhost:14000 --auto
   ```

3. **Manual verification**:
   ```bash
   # Test auth bypass
   curl "http://localhost:14000/identity/rest/v1/users;.wadl"
   ```

## Production Deployment

### Security Considerations

**DO NOT** deploy this vulnerable application in production environments.

This challenge is for:
- ✅ Educational purposes
- ✅ CTF competitions
- ✅ Security training
- ✅ Isolated lab environments

**NEVER** for:
- ❌ Production systems
- ❌ Public-facing servers
- ❌ Real corporate networks

### Isolated Network

Run in isolated network:

```yaml
networks:
  ctf-network:
    driver: bridge
    internal: true  # No internet access
```

### Resource Limits

Add resource constraints:

```yaml
services:
  oracle-iam:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          memory: 256M
```

## CTF Platform Integration

### HTB/THM Style Deployment

```bash
# Set custom flag
export CTF_FLAG="HTB{your_flag_here}"

# Run with custom flag
docker run -d \
  -p 14000:14000 \
  -e FLAG="${CTF_FLAG}" \
  --name challenge \
  oracle-iam-ctf
```

### Flag Rotation

```bash
# Generate random flag
FLAG="FLAG{$(openssl rand -hex 16)}"

# Deploy with new flag
docker-compose down
sed -i "s/FLAG=.*/FLAG=${FLAG}/" docker-compose.yml
docker-compose up -d
```

### Network Isolation

```yaml
networks:
  challenge-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

## Monitoring

### Container Logs

```bash
# Real-time logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100

# Logs for specific service
docker-compose logs oracle-iam
```

### Resource Usage

```bash
# CPU and memory usage
docker stats oracle-iam-vulnerable

# Detailed info
docker inspect oracle-iam-vulnerable
```

## Cleanup

### Stop and Remove

```bash
# Stop containers
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

### Complete Cleanup

```bash
# Remove everything
docker-compose down -v --rmi all --remove-orphans

# Remove dangling images
docker image prune -f

# Remove unused volumes
docker volume prune -f
```

## Advanced Configuration

### Multi-Instance Deployment

```yaml
version: '3.8'

services:
  oracle-iam-1:
    build: .
    ports:
      - "14001:14000"
    environment:
      - FLAG=FLAG{instance_1}

  oracle-iam-2:
    build: .
    ports:
      - "14002:14000"
    environment:
      - FLAG=FLAG{instance_2}
```

### Load Balancer Setup

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - oracle-iam-1
      - oracle-iam-2

  oracle-iam-1:
    build: .
    expose:
      - "14000"

  oracle-iam-2:
    build: .
    expose:
      - "14000"
```

## Support

For issues or questions:
1. Check logs: `docker-compose logs`
2. Verify network: `docker network inspect ctf-network`
3. Test manually: Use curl commands from README.md
4. Review SOLUTION.md for exploitation steps

## References

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Flask Documentation](https://flask.palletsprojects.com/)
