# 🚀 Deployment Guide

## Quick Start

### Local Development
```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Unix/MacOS

# 2. Install dependencies
pip install -r requirements.txt



# 4. Run the application
python app.py
```

### Production Deployment

#### Option 1: Traditional Server
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_DEBUG=False
export SECRET_KEY="your-secure-secret-key"

# Run with production server
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Option 2: Docker
```bash
# Build and run
docker build -t por-automator .
docker run -p 5000:5000 por-automator
```

#### Option 3: Railway/Heroku
- The `Procfile` and `runtime.txt` are already configured
- Just push to your repository and deploy

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_DEBUG` | `True` | Enable debug mode |
| `SECRET_KEY` | `dev-secret-key` | Flask secret key |
| `DATABASE_URL` | `sqlite:///a&p_por.db` | Database connection |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `5000` | Server port |

## Database Setup

The application automatically creates the database on first run. For production:

1. **SQLite** (default): No setup required
2. **PostgreSQL**: Set `DATABASE_URL` environment variable
3. **MySQL**: Set `DATABASE_URL` environment variable



## Security Considerations

- Change `SECRET_KEY` in production
- Set `FLASK_DEBUG=False` in production
- Use HTTPS in production
- Restrict file uploads to trusted sources
- Monitor file upload sizes

## Performance Tuning

- **Database**: Add indexes for large datasets
- **File Processing**: Monitor memory usage for large files
- **Classification**: Pattern matching is optimized for speed
- **Caching**: Consider Redis for session storage

## Monitoring

- Check application logs
- Monitor database performance
- Track classification accuracy
- Monitor file upload success rates

## Troubleshooting

### Common Issues
1. **Classification Issues**: Check pattern matching rules in app.py
2. **Database Errors**: Check file permissions and database URL
3. **File Upload Issues**: Verify file size limits and allowed extensions
4. **Memory Issues**: Reduce `RECORDS_PER_PAGE` in config.py

### Logs
- Application logs are written to console
- Set `LOG_LEVEL=DEBUG` for detailed logging
- Check system logs for server errors

## Support

For deployment issues:
1. Check the README.md for detailed setup instructions
2. Verify all dependencies are installed
3. Check environment variables are set correctly
4. Review application logs for error messages
