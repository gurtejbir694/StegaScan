# Stegascan REST API

A high-performance REST API for detecting and analyzing steganography in digital media files.

## Features

- 🔍 **Multi-format Support**: Images, Audio, Video, and Text documents
- 🚀 **Async Processing**: Non-blocking analysis with result polling
- 🎯 **Quick Scan**: Fast preliminary check for suspicious files
- 📊 **Detailed Analysis**: Comprehensive steganography detection
- 🔐 **Magic Bytes**: Embedded file and polyglot detection
- 📈 **LSB Analysis**: Least Significant Bit steganography detection
- 🎵 **Spectrogram**: Hidden audio message detection
- 🎬 **Video Analysis**: Frame-by-frame suspicious pattern detection

## Quick Start

### Installation

1. Add to your `Cargo.toml` workspace:

```toml
[workspace]
members = ["analyzers", "parsers", "stegascan-api"]
```

2. Build and run:

```bash
cd stegascan-api
cargo run --release
```

The API will start on `http://localhost:3000`

## API Endpoints

### 1. Health Check

```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 2. Quick Scan

Fast preliminary scan for suspicious files.

```bash
POST /api/v1/quick-scan
Content-Type: multipart/form-data

file: <binary data>
```

**Example with cURL:**
```bash
curl -X POST http://localhost:3000/api/v1/quick-scan \
  -F "file=@suspicious_image.png"
```

**Response:**
```json
{
  "filename": "suspicious_image.png",
  "file_size": 524288,
  "file_type": "image/png",
  "detected_format": "PNG image",
  "suspicious": true,
  "risk_level": "medium",
  "findings": [
    "Multiple file signatures detected",
    "Embedded JPEG found at offset 0x1234"
  ],
  "embedded_files_count": 2,
  "scan_timestamp": "2024-01-15T10:30:00Z"
}
```

### 3. Full Analysis (Async)

Comprehensive analysis with detailed results.

```bash
POST /api/v1/analyze
Content-Type: multipart/form-data

file: <binary data>
video_sample_rate: 30 (optional)
verbose: false (optional)
```

**Example with cURL:**
```bash
curl -X POST http://localhost:3000/api/v1/analyze \
  -F "file=@test_video.mp4" \
  -F "video_sample_rate=30"
```

**Response (Immediate):**
```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "message": "Analysis started. Use GET /api/v1/analyze/:id to check status",
  "filename": "test_video.mp4",
  "file_size": 10485760
}
```

### 4. Get Analysis Result

Retrieve results from a previous analysis.

```bash
GET /api/v1/analyze/{analysis_id}
```

**Example:**
```bash
curl http://localhost:3000/api/v1/analyze/550e8400-e29b-41d4-a716-446655440000
```

**Response (Processing):**
```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "message": "Analysis still in progress"
}
```

**Response (Complete):**
```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": {
    "file_info": {
      "path": "/tmp/...",
      "size_bytes": 524288,
      "detected_type": "Image",
      "extension": "png"
    },
    "magic_bytes_analysis": {
      "primary_format": "PNG image",
      "has_multiple_formats": true,
      "has_suspicious_data": true,
      "embedded_files": [...],
      "suspicious_findings": [...]
    },
    "format_specific_analysis": {
      "type": "Image",
      "exif_metadata": {...},
      "lsb_analysis": {
        "is_suspicious": true,
        "channels": [
          {
            "channel_name": "Red",
            "chi_square_score": 125.4,
            "entropy_score": 0.92
          }
        ]
      },
      "dimensions": {
        "width": 1920,
        "height": 1080
      }
    },
    "summary": {
      "steganography_detected": true,
      "confidence_level": "high",
      "threat_indicators": [
        "LSB analysis indicates hidden data",
        "Multiple file formats detected"
      ],
      "recommendations": [
        "Further investigation recommended",
        "Consider specialized tools"
      ]
    },
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Response Models

### File Info
```json
{
  "path": "string",
  "size_bytes": 0,
  "detected_type": "Image|Audio|Video|Text",
  "extension": "string|null"
}
```

### Image Analysis
```json
{
  "type": "Image",
  "exif_metadata": {
    "fields_found": 0,
    "has_thumbnail": false,
    "suspicious_fields": []
  },
  "lsb_analysis": {
    "is_suspicious": false,
    "channels": []
  },
  "dimensions": {
    "width": 0,
    "height": 0
  }
}
```

### Audio Analysis
```json
{
  "type": "Audio",
  "sample_count": 0,
  "id3_analysis": {
    "title": "string|null",
    "suspicious_frames": []
  },
  "spectrogram_analysis": {
    "high_frequency_energy": 0.0,
    "hidden_message_detected": false,
    "suspicious_patterns": []
  }
}
```

### Video Analysis
```json
{
  "type": "Video",
  "frames_processed": 0,
  "errors_encountered": 0,
  "suspicious_frames": []
}
```

## Usage Examples

### Python Client

```python
import requests

# Quick Scan
with open('suspicious.png', 'rb') as f:
    response = requests.post(
        'http://localhost:3000/api/v1/quick-scan',
        files={'file': f}
    )
    print(response.json())

# Full Analysis
with open('test.mp4', 'rb') as f:
    response = requests.post(
        'http://localhost:3000/api/v1/analyze',
        files={'file': f},
        data={'video_sample_rate': '30'}
    )
    analysis_id = response.json()['analysis_id']

# Poll for results
import time
while True:
    response = requests.get(
        f'http://localhost:3000/api/v1/analyze/{analysis_id}'
    )
    result = response.json()
    
    if result['status'] == 'completed':
        print(result['result'])
        break
    
    time.sleep(2)
```

### JavaScript Client

```javascript
// Quick Scan
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const quickScan = await fetch('http://localhost:3000/api/v1/quick-scan', {
  method: 'POST',
  body: formData
});

const scanResult = await quickScan.json();
console.log(scanResult);

// Full Analysis
const analysis = await fetch('http://localhost:3000/api/v1/analyze', {
  method: 'POST',
  body: formData
});

const { analysis_id } = await analysis.json();

// Poll for results
async function pollResult(id) {
  const response = await fetch(`http://localhost:3000/api/v1/analyze/${id}`);
  const result = await response.json();
  
  if (result.status === 'completed') {
    return result.result;
  }
  
  await new Promise(resolve => setTimeout(resolve, 2000));
  return pollResult(id);
}

const finalResult = await pollResult(analysis_id);
console.log(finalResult);
```

## Configuration

### Environment Variables

- `RUST_LOG`: Set logging level (default: `info`)
  ```bash
  RUST_LOG=debug cargo run
  ```

- `PORT`: API port (default: `3000`)
  ```bash
  PORT=8080 cargo run
  ```

### Video Analysis Parameters

- `video_sample_rate`: Analyze every Nth frame (default: `30`)
  - Lower values = more thorough but slower
  - Higher values = faster but may miss frames

## Performance Notes

1. **Quick Scan**: ~100ms for typical files
2. **Image Analysis**: ~1-2 seconds for 1080p images
3. **Audio Analysis**: ~3-5 seconds for 3-minute audio files
4. **Video Analysis**: ~30 seconds per minute of video (at sample_rate=30)

## Error Handling

All errors return appropriate HTTP status codes:

- `400 Bad Request`: Missing or invalid file
- `422 Unprocessable Entity`: Analysis failed
- `500 Internal Server Error`: Server error
- `202 Accepted`: Analysis in progress (use polling)

## Production Deployment

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p stegascan-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates
COPY --from=builder /app/target/release/stegascan-api /usr/local/bin/
EXPOSE 3000
CMD ["stegascan-api"]
```

### Recommendations

1. Use Redis/PostgreSQL for result caching (not in-memory)
2. Add authentication (JWT, API keys)
3. Implement rate limiting
4. Set up file size limits
5. Configure CORS for specific origins
6. Add request timeouts
7. Use background job queue (e.g., Sidekiq, Bull)

## License

MIT License - see LICENSE file for details
